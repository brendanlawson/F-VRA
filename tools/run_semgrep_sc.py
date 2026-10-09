#!/usr/bin/env python3
"""Run Semgrep Supply Chain (SCA + reachability) over every project source tree.

Unlike osv-scanner/pip-audit (see run_scanners.py), Semgrep Supply Chain needs the
*source code*, not just a lockfile, so it can do reachability analysis. In this
workspace the project source trees default to data/raw/projects/<project>, so we
scan those folders directly.

Semgrep Supply Chain is a hosted product: `semgrep ci --supply-chain` requires a
SEMGREP_APP_TOKEN, downloads the SCA rules, scans locally, and uploads findings to the
Semgrep AppSec Platform. We run it through the official `semgrep/semgrep` Docker image so
it works reliably on Windows.

IMPORTANT — reachability lives in two places:
  * The local `--json-output` JSON has per-advisory detail (package, version, severity,
    direct/transitive, whether a reachability *rule* exists) but `reachable` is always
    false locally — the final reachable/unreachable/undetermined verdict is computed during
    the upload/finalize step and printed in the CLI text output.
  * So we save BOTH: the JSON (machine-readable detail) AND the full CLI text (accurate
    "N Reachable / N Undetermined / N Unreachable" counts), and aggregate from the text.

Layout (under data/raw/sca/legacy_inventory/):
  semgrep-supply-chain/<project>.json     raw semgrep JSON (--json-output)
  logs/<project>.semgrep-sc.log           cmd (token redacted) + exit code + stdout + stderr
  semgrep_checkpoint.json                 {project: {status, findings, reachable, ...}}, incremental
  semgrep_sc_summary.csv                  aggregated per-project counts
  run.log                                 shared overall progress log

Prerequisites:
  * Docker Desktop running.
  * SEMGREP_APP_TOKEN set (env var, or persisted Windows User env — the script reads both).
  * `docker pull semgrep/semgrep` done once.

Usage:
  python tools/run_semgrep_sc.py                       # all projects (resume-aware)
  python tools/run_semgrep_sc.py spiral-project__ihatemoney   # a single project
  python tools/run_semgrep_sc.py --force               # ignore checkpoint, re-run all
  python tools/run_semgrep_sc.py --retry               # re-run only failed/timed-out
"""
from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECTS = Path(os.getenv("F_VRA_LEGACY_PROJECTS_ROOT", ROOT / "data" / "raw" / "projects"))
SCANS = Path(os.getenv("F_VRA_LEGACY_SCA_ROOT", ROOT / "data" / "_scans"))
SC_DIR = SCANS / "semgrep-supply-chain"
LOG_DIR = SCANS / "logs"
CHECKPOINT = SCANS / "semgrep_checkpoint.json"
RUN_LOG = SCANS / "run.log"
SUMMARY = SCANS / "semgrep_sc_summary.csv"

IMAGE = "semgrep/semgrep"
PER_PROJECT_TIMEOUT = 3600  # seconds (huge repos do a slow `git status` over the Docker mount)
# `semgrep ci` runs `git status`/`git rev-parse` inside the container; on Windows the
# Docker bind mount is slow, so big repos (checkmk, airflow, saleor) blow past git's
# default 300s timeout. Bump it well above that.
GIT_TIMEOUT = 1800
OK_STATES = {"clean", "findings"}  # checkpoint states that count as done

# native lockfiles Semgrep Supply Chain recognises (all support reachability for Python)
NATIVE_LOCKS = ("uv.lock", "Pipfile.lock", "poetry.lock")

# CLI text summary patterns
_RE_REACHABLE = re.compile(r"(\d+)\s+Reachable Supply Chain Findings")
_RE_UNDETERMINED = re.compile(r"(\d+)\s+Undetermined Supply Chain Findings")
_RE_UNREACHABLE = re.compile(r"(\d+)\s+Unreachable Supply Chain Findings")
_RE_FINDINGS = re.compile(r"Findings:\s+(\d+)\s+\((\d+)\s+blocking\)")


def log(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with RUN_LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def load_checkpoint() -> dict:
    if CHECKPOINT.exists():
        try:
            return json.loads(CHECKPOINT.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_checkpoint(cp: dict) -> None:
    tmp = CHECKPOINT.with_suffix(".tmp")
    tmp.write_text(json.dumps(cp, indent=2), encoding="utf-8")
    tmp.replace(CHECKPOINT)


def write_log(project: str, cmd: list[str], proc, extra: str = "") -> None:
    redacted = [re.sub(r"^(SEMGREP_APP_TOKEN=).*", r"\1***", c) for c in cmd]
    p = LOG_DIR / f"{project}.semgrep-sc.log"
    parts = [
        f"# project: {project}", f"# scanner: semgrep-supply-chain", f"# time: {time.ctime()}",
        "$ " + " ".join(redacted),
        f"# exit code: {getattr(proc, 'returncode', 'n/a')}",
    ]
    if extra:
        parts.append(f"# note: {extra}")
    parts += ["=== STDOUT ===", getattr(proc, "stdout", "") or "",
              "=== STDERR ===", getattr(proc, "stderr", "") or ""]
    p.write_text("\n".join(parts), encoding="utf-8")


def get_token() -> str | None:
    """Read SEMGREP_APP_TOKEN from the process env, falling back to the persisted
    Windows *User* environment (so a token set after this shell started still works)."""
    tok = os.environ.get("SEMGREP_APP_TOKEN")
    if tok:
        return tok
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
                val, _ = winreg.QueryValueEx(k, "SEMGREP_APP_TOKEN")
                return val
        except OSError:
            return None
    return None


def has_scannable_manifest(pdir: Path) -> tuple[bool, list[str], str]:
    """Decide what Semgrep can scan in this project.
    Returns (ok, extra_docker_args, note).
      * native lock (uv.lock/Pipfile.lock/poetry.lock) -> scan as-is (pinned).
      * requirements*.txt present -> scan, add --allow-local-builds (may not be fully pinned).
      * only pyproject.toml -> mount the inventory's pinned requirements so Semgrep sees a
        lockfile; if that's missing, caller should skip.
    """
    for lock in NATIVE_LOCKS:
        if (pdir / lock).exists():
            return True, [], f"native lock: {lock}"
    if list(pdir.glob("requirements*.txt")) or list(pdir.glob("requirements/*.txt")):
        return True, ["__ALLOW_LOCAL_BUILDS__"], "requirements.txt (--allow-local-builds)"
    # fallback: inventory pinned requirements (e.g. bookwyrm has only pyproject.toml)
    pinned = PROJECTS / pdir.name / "requirements.pinned.txt"
    if pinned.exists():
        mount = f"{pinned.as_posix()}:/src/requirements.txt:ro"
        return True, ["-v", mount, "__ALLOW_LOCAL_BUILDS__"], "inventory pinned requirements (mounted)"
    return False, [], "no scannable manifest (only pyproject.toml, no inventory pin)"


def parse_text_counts(stdout: str) -> dict:
    def first(rx):
        m = rx.search(stdout)
        return int(m.group(1)) if m else 0
    reachable = first(_RE_REACHABLE)
    undetermined = first(_RE_UNDETERMINED)
    unreachable = first(_RE_UNREACHABLE)
    fm = _RE_FINDINGS.search(stdout)
    findings = int(fm.group(1)) if fm else (reachable + undetermined + unreachable)
    blocking = int(fm.group(2)) if fm else 0
    return {"reachable": reachable, "undetermined": undetermined,
            "unreachable": unreachable, "findings": findings, "blocking": blocking}


def parse_json_detail(jpath: Path) -> dict:
    """Per-advisory detail from the local JSON: severity + transitivity breakdown,
    distinct vulnerable packages, and how many advisories have a reachability rule."""
    try:
        data = json.loads(jpath.read_text(encoding="utf-8"))
    except Exception:
        return {}
    results = data.get("results", [])
    sev = {"HIGH": 0, "MODERATE": 0, "LOW": 0, "CRITICAL": 0}
    direct = transitive = with_rule = 0
    pkgs = set()
    for r in results:
        meta = r.get("extra", {}).get("metadata", {})
        s = (meta.get("sca-severity") or "").upper()
        if s in sev:
            sev[s] += 1
        sca = r.get("extra", {}).get("sca_info", {})
        if sca.get("reachability_rule"):
            with_rule += 1
        dep = sca.get("dependency_match", {}).get("found_dependency", {})
        if dep.get("package"):
            pkgs.add((dep["package"], dep.get("version")))
        if dep.get("transitivity") == "direct":
            direct += 1
        elif dep.get("transitivity") == "transitive":
            transitive += 1
    return {"json_results": len(results), "sev": sev, "direct": direct,
            "transitive": transitive, "with_reach_rule": with_rule,
            "vuln_pkgs": len(pkgs)}


def run_semgrep(project: str, pdir: Path, token: str) -> dict:
    ok, extra, note = has_scannable_manifest(pdir)
    if not ok:
        return {"status": "skip", "note": note}

    out_host = SC_DIR / f"{project}.json"
    if out_host.exists():
        out_host.unlink()

    cmd = [
        "docker", "run", "--rm",
        "-e", f"SEMGREP_APP_TOKEN={token}",
        "-e", f"SEMGREP_REPO_NAME={project}",   # distinct project on the platform dashboard
        "-e", f"SEMGREP_GIT_COMMAND_TIMEOUT={GIT_TIMEOUT}",
        "-v", f"{pdir.as_posix()}:/src",
        "-v", f"{SC_DIR.as_posix()}:/out",
    ]
    # inject any extra mounts requested by manifest detection (before the image name)
    allow_local = False
    i = 0
    while i < len(extra):
        if extra[i] == "__ALLOW_LOCAL_BUILDS__":
            allow_local = True
            i += 1
        else:  # a "-v" / mount pair
            cmd += [extra[i], extra[i + 1]]
            i += 2
    cmd += ["-w", "/src", IMAGE,
            "semgrep", "ci", "--supply-chain",
            f"--json-output=/out/{project}.json"]
    if allow_local:
        cmd.append("--allow-local-builds")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=PER_PROJECT_TIMEOUT, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        write_log(project, cmd, e, f"TIMEOUT@{PER_PROJECT_TIMEOUT}s ({note})")
        return {"status": "timeout", "note": note}

    write_log(project, cmd, proc, note)

    if not out_host.exists():
        # semgrep ci returns 1 for blocking findings (still a success); a missing JSON
        # means a real failure (bad token, docker error, parse failure, ...).
        return {"status": "error", "rc": proc.returncode, "note": note}

    res = {"note": note, "rc": proc.returncode}
    res.update(parse_text_counts(proc.stdout or ""))
    res.update(parse_json_detail(out_host))
    res["status"] = "findings" if res.get("findings", 0) else "clean"
    return res


def main() -> None:
    args = list(sys.argv[1:])
    force = "--force" in args
    retry = "--retry" in args
    args = [a for a in args if a not in ("--force", "--retry")]

    for d in (SC_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)

    token = get_token()
    if not token:
        log("!! SEMGREP_APP_TOKEN not found (env or Windows User env). Aborting.")
        sys.exit(2)

    if not PROJECTS.exists():
        log(f"!! source root not found: {PROJECTS}. Aborting.")
        sys.exit(2)

    targets = args or sorted(
        d.name for d in PROJECTS.iterdir()
        if d.is_dir() and "__" in d.name and not d.name.startswith("_") and d.name != "tools"
    )

    cp = load_checkpoint()
    log(f"=== semgrep supply-chain run: {len(targets)} projects "
        f"(force={force}, retry={retry}) ===")

    for project in targets:
        pdir = PROJECTS / project
        if not pdir.is_dir():
            log(f"!! {project}: missing inventory source dir, skip"); continue
        prev = cp.get(project, {})
        done = prev.get("status") in OK_STATES
        if done and not force and not retry:
            log(f"-- {project}: skip (checkpoint={prev.get('status')})"); continue
        if retry and done and not force:
            log(f"-- {project}: skip (already {prev.get('status')})"); continue

        t0 = time.time()
        res = run_semgrep(project, pdir, token)
        res["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
        res["secs"] = round(time.time() - t0, 1)
        cp[project] = res
        save_checkpoint(cp)  # incremental: crash-safe
        log(f">> {project}: {res.get('status')} "
            f"findings={res.get('findings','-')} "
            f"reachable={res.get('reachable','-')} "
            f"undetermined={res.get('undetermined','-')} "
            f"unreachable={res.get('unreachable','-')} "
            f"({res.get('secs')}s)")

    # aggregate
    rows = []
    for project in sorted(cp):
        c = cp[project]
        sev = c.get("sev", {}) or {}
        rows.append({
            "project": project,
            "status": c.get("status", "-"),
            "findings": c.get("findings", ""),
            "reachable": c.get("reachable", ""),
            "undetermined": c.get("undetermined", ""),
            "unreachable": c.get("unreachable", ""),
            "blocking": c.get("blocking", ""),
            "vuln_pkgs": c.get("vuln_pkgs", ""),
            "direct": c.get("direct", ""),
            "transitive": c.get("transitive", ""),
            "sev_critical": sev.get("CRITICAL", ""),
            "sev_high": sev.get("HIGH", ""),
            "sev_moderate": sev.get("MODERATE", ""),
            "sev_low": sev.get("LOW", ""),
            "note": c.get("note", ""),
        })
    cols = ["project", "status", "findings", "reachable", "undetermined", "unreachable",
            "blocking", "vuln_pkgs", "direct", "transitive",
            "sev_critical", "sev_high", "sev_moderate", "sev_low", "note"]
    with SUMMARY.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader(); w.writerows(rows)

    tot_f = sum(int(r["findings"] or 0) for r in rows)
    tot_r = sum(int(r["reachable"] or 0) for r in rows)
    log(f"=== done. total findings={tot_f}, total reachable={tot_r} -> {SUMMARY} ===")


if __name__ == "__main__":
    main()
