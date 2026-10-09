#!/usr/bin/env python3
"""Run pip-audit and osv-scanner across every project inventory.

Results are written per scanner into separate folders, with per-project logs and a
checkpoint so an interrupted run can resume (already-completed (project, scanner)
pairs are skipped).

Layout (under data/raw/sca/legacy_inventory/):
  pip-audit/<project>.json        raw pip-audit JSON
  osv-scanner/<project>.json      raw osv-scanner JSON
  logs/<project>.<scanner>.log    cmd + exit code + stdout + stderr
  checkpoint.json                 {project: {scanner: {status, vulns, ...}}}, written incrementally
  vuln_summary.csv                aggregated per-project counts
  run.log                         overall progress (also echoed to stdout)

Usage:
  python tools/run_scanners.py                  # all projects, both scanners (resume-aware)
  python tools/run_scanners.py saleor__saleor   # a single project
  python tools/run_scanners.py --only pip-audit
  python tools/run_scanners.py --only osv-scanner
  python tools/run_scanners.py --force          # ignore checkpoint, re-run everything
  python tools/run_scanners.py --retry          # re-run only failed/timed-out entries
"""
from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECTS = Path(os.getenv("F_VRA_LEGACY_PROJECTS_ROOT", ROOT / "data" / "raw" / "projects"))
SCANS = Path(os.getenv("F_VRA_LEGACY_SCA_ROOT", ROOT / "data" / "_scans"))
PA_DIR = SCANS / "pip-audit"
OSV_DIR = SCANS / "osv-scanner"
LOG_DIR = SCANS / "logs"
CHECKPOINT = SCANS / "checkpoint.json"
RUN_LOG = SCANS / "run.log"

VENV = ROOT / "tools" / ".venv"
PIP_AUDIT = VENV / "Scripts" / "pip-audit.exe"
VENV_PY = VENV / "Scripts" / "python.exe"
if not PIP_AUDIT.exists():
    PIP_AUDIT = VENV / "bin" / "pip-audit"  # posix venv
    VENV_PY = VENV / "bin" / "python"
def _osv_scanner() -> str:
    configured = os.getenv("F_VRA_OSV_SCANNER")
    if configured:
        return configured
    found = shutil.which("osv-scanner")
    if found:
        return found
    if sys.platform == "win32":
        winget_dir = Path.home() / "AppData" / "Local" / "Microsoft" / "WinGet" / "Packages"
        matches = list(winget_dir.glob("Google.OSVScanner_*/*osv-scanner.exe"))
        if matches:
            return str(matches[0])
    local = ROOT / "tools" / "bin" / ("osv-scanner.exe" if sys.platform == "win32" else "osv-scanner")
    return str(local)


OSV = _osv_scanner()

PER_PROJECT_TIMEOUT = 1800  # seconds (osv-scanner)
PA_ATTEMPT_TIMEOUT = 120    # per uv dry-run prefilter pass
PA_AUDIT_TIMEOUT = 420      # per single pip-audit invocation (bail on hang)
PA_MAX_DROPS = 25           # max iterative drops of uninstallable pins
PA_NET_RETRIES = 2          # pip-audit retries on transient network errors
PA_AUDIT_ATTEMPTS = 6       # max pip-audit attempts (drop-on-reject + net retries)
# package names pip-audit's pip rejects as not installable on this interpreter
_NOMATCH = re.compile(
    r"(?:No matching distribution found for|"
    r"Could not find a version that satisfies the requirement)\s+([A-Za-z0-9][A-Za-z0-9._-]*)")
OK_STATES = {"ok", "clean", "vulns"}  # checkpoint states that count as done
TMP = SCANS / "_tmp"

UV = shutil.which("uv") or "uv"
_NORM = re.compile(r"[-_.]+")
# package names with no usable wheel for this interpreter/platform.
# uv: "Because <name>==<ver> has no usable wheels"; pip fallback messages too.
_NOWHEEL = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._-]*)==[^\s]+ has no usable wheels|"
    r"(?:Could not find a version that satisfies the requirement|"
    r"No matching distribution found for)\s+([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize(n: str) -> str:
    return _NORM.sub("-", n).strip().lower()


def split_blocks(text: str):
    """Split a pinned requirements file into (normalized_name, block_text) blocks.
    A block = a `name==ver` line plus its indented `--hash`/continuation lines."""
    blocks, cur, name = [], [], None
    for raw in text.splitlines():
        if raw[:1] not in (" ", "\t") and "==" in raw and not raw.lstrip().startswith(("#", "-")):
            if cur:
                blocks.append((name, "\n".join(cur)))
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", raw)
            name = normalize(m.group(1)) if m else None
            cur = [raw]
        else:
            cur.append(raw)
    if cur:
        blocks.append((name, "\n".join(cur)))
    return blocks


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
    tmp = CHECKPOINT.with_name(f"{CHECKPOINT.stem}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(cp, indent=2), encoding="utf-8")
    for attempt in range(5):
        try:
            tmp.replace(CHECKPOINT)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.5)


def write_log(project: str, scanner: str, cmd: list[str], proc, extra: str = "") -> None:
    p = LOG_DIR / f"{project}.{scanner}.log"
    parts = [
        f"# project: {project}", f"# scanner: {scanner}", f"# time: {time.ctime()}",
        "$ " + " ".join(cmd),
        f"# exit code: {getattr(proc, 'returncode', 'n/a')}",
    ]
    if extra:
        parts.append(f"# note: {extra}")
    parts += ["=== STDOUT ===", getattr(proc, "stdout", "") or "",
              "=== STDERR ===", getattr(proc, "stderr", "") or ""]
    p.write_text("\n".join(parts), encoding="utf-8")


def osv_lockfile_arg(pdir: Path) -> str:
    if (pdir / "uv.lock").exists():
        return str(pdir / "uv.lock")
    if (pdir / "Pipfile.lock").exists():
        return str(pdir / "Pipfile.lock")
    return f"requirements.txt:{pdir / 'requirements.pinned.txt'}"


def _installable_skips(work: Path, blocks, project: str) -> tuple[list[str], list[str]]:
    """Find pins with no usable wheel for this interpreter using `uv` resolution
    with `--only-binary :all:` (fast, never builds sdists). Iteratively drops them
    so pip-audit can later audit the wheel-installable subset without build failures.
    Returns (skipped_names, attempt_logs)."""
    skipped: list[str] = []
    logs: list[str] = []
    for _ in range(PA_MAX_DROPS + 1):
        keep = [b for n, b in blocks if n not in skipped]
        work.write_text("\n".join(keep) + "\n", encoding="utf-8")
        cmd = [UV, "pip", "install", "--dry-run", "--no-deps", "--only-binary", ":all:",
               "--python", str(VENV_PY), "-r", str(work)]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=PA_ATTEMPT_TIMEOUT)
        except subprocess.TimeoutExpired:
            logs.append("uv dry-run TIMEOUT"); return skipped, logs
        logs.append(f"--- uv dry-run (skipped={len(skipped)}) rc={p.returncode} ---\n"
                    + (p.stderr or "")[-600:])
        if p.returncode == 0:
            return skipped, logs
        found = {normalize(a or b) for a, b in _NOWHEEL.findall(p.stderr or "") if (a or b)}
        new = sorted(found - set(skipped))
        if not new:
            return skipped, logs  # non-wheel error (version conflict, etc.); bail
        skipped.extend(new)
    return skipped, logs


def run_pip_audit(project: str, pdir: Path) -> dict:
    """Audit the pinned set with pip-audit (OSV service).

    The *universal* lock may contain pins with no installable distribution here
    (py3.13-only or other-OS wheels), which would break pip-audit's pip resolution.
    We pre-filter those out cheaply (venv pip --dry-run) and audit the maximal
    installable subset; dropped packages are recorded in `skipped`."""
    req = pdir / "requirements.pinned.txt"
    out = PA_DIR / f"{project}.json"
    if not req.exists():
        lock_files = ("pylock.toml", "uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock")
        cmd = [
            str(PIP_AUDIT),
            str(pdir),
            "-s",
            "osv",
            "--progress-spinner",
            "off",
            "-f",
            "json",
            "-o",
            str(out),
        ]
        if any((pdir / name).exists() for name in lock_files):
            cmd.insert(2, "--locked")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=PA_AUDIT_TIMEOUT)
        except subprocess.TimeoutExpired as e:
            write_log(project, "pip-audit", cmd, e, "TIMEOUT project-path fallback")
            return {"status": "timeout", "note": "project-path fallback"}
        write_log(project, "pip-audit", cmd, proc, "project-path fallback")
        if not out.exists():
            return {
                "status": "skip" if "no dependencies found" in ((proc.stderr or "") + (proc.stdout or "")).lower() else "error",
                "rc": proc.returncode,
                "note": "project-path fallback",
            }
        data = json.loads(out.read_text(encoding="utf-8"))
        deps = data.get("dependencies", [])
        vulns = sum(len(d.get("vulns", []) or []) for d in deps)
        vpkgs = sum(1 for d in deps if d.get("vulns"))
        return {
            "status": "vulns" if vulns else "clean",
            "scanned": len(deps),
            "vulns": vulns,
            "vuln_pkgs": vpkgs,
            "note": "project-path fallback",
        }

    TMP.mkdir(parents=True, exist_ok=True)
    blocks = split_blocks(req.read_text(encoding="utf-8"))
    work = TMP / f"{project}.req.txt"
    skipped, pre_logs = _installable_skips(work, blocks, project)

    (LOG_DIR / f"{project}.pip-audit.prefilter.log").write_text(
        "\n\n".join(pre_logs), encoding="utf-8")

    cmd = [str(PIP_AUDIT), "-r", str(work), "--no-deps", "-s", "osv",
           "--progress-spinner", "off", "-f", "json", "-o", str(out)]
    # uv and pip-audit's pip can disagree on installability (e.g. Requires-Python).
    # So also drop packages pip-audit rejects and retry; plus retry transient network
    # errors (its OSV service makes one HTTP call per package).
    proc = None
    net_used = 0
    for attempt in range(PA_AUDIT_ATTEMPTS):
        keep = [b for n, b in blocks if n not in skipped]
        work.write_text("\n".join(keep) + "\n", encoding="utf-8")
        if out.exists():
            out.unlink()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=PA_AUDIT_TIMEOUT)
        except subprocess.TimeoutExpired as e:
            # a single pip-audit run hung (OSV per-package calls stalled); bail fast,
            # osv-scanner still covers this project.
            write_log(project, "pip-audit", cmd, e, f"TIMEOUT@{PA_AUDIT_TIMEOUT}s (skipped={skipped})")
            return {"status": "timeout", "skipped": skipped}
        if out.exists():
            break
        rejected = sorted({normalize(x) for x in _NOMATCH.findall(proc.stderr or "")} - set(skipped))
        net = re.search(r"Traceback|urllib3|ConnectionError|Max retries|timed out|"
                        r"RemoteDisconnected|ConnectionResetError", proc.stderr or "")
        write_log(project, "pip-audit", cmd, proc,
                  f"attempt {attempt+1} reject={rejected} net={bool(net)} skipped={skipped}")
        if rejected:
            skipped.extend(rejected); continue          # drop pip-rejected pins, retry
        if net and net_used < PA_NET_RETRIES:
            net_used += 1; continue                       # transient network: retry
        break                                             # unrecoverable

    if not out.exists():
        return {"status": "error", "rc": getattr(proc, "returncode", None), "skipped": skipped}
    write_log(project, "pip-audit", cmd, proc,
              f"OK skipped({len(skipped)})={skipped}")
    data = json.loads(out.read_text(encoding="utf-8"))
    deps = data.get("dependencies", [])
    vulns = sum(len(d.get("vulns", []) or []) for d in deps)
    vpkgs = sum(1 for d in deps if d.get("vulns"))
    res = {"status": "vulns" if vulns else "clean", "scanned": len(deps),
           "vulns": vulns, "vuln_pkgs": vpkgs}
    if skipped:
        res["skipped"] = skipped
    return res


def _count_osv_vulns(data: dict) -> tuple[int, int, int]:
    vulns = vpkgs = scanned = 0
    if not isinstance(data, dict):
        return scanned, vulns, vpkgs
    for res in data.get("results", []) or []:
        for pkg in res.get("packages", []):
            scanned += 1
            v = pkg.get("vulnerabilities", []) or []
            if v:
                vpkgs += 1
                vulns += len(v)
        for pkg in res.get("packages_with_vulnerabilities", []) or []:
            scanned += 1
            groups = pkg.get("groups", []) or []
            count = sum(len(group.get("vulnerabilities", []) or []) for group in groups)
            if count:
                vpkgs += 1
                vulns += count
    return scanned, vulns, vpkgs


def run_osv(project: str, pdir: Path) -> dict:
    out = OSV_DIR / f"{project}.json"
    cmd = [
        str(OSV),
        "scan",
        "source",
        "--recursive",
        "--allow-no-lockfiles",
        "--format",
        "json",
        "--output-file",
        str(out),
        str(pdir),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=PER_PROJECT_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        write_log(project, "osv-scanner", cmd, e, "TIMEOUT")
        return {"status": "timeout"}
    write_log(project, "osv-scanner", cmd, proc)
    if not out.exists():
        return {"status": "error", "rc": proc.returncode}
    data = json.loads(out.read_text(encoding="utf-8"))
    scanned, vulns, vpkgs = _count_osv_vulns(data)
    return {"status": "vulns" if vulns else "clean", "scanned": scanned,
            "vulns": vulns, "vuln_pkgs": vpkgs}


def main() -> None:
    args = list(sys.argv[1:])
    force = "--force" in args
    retry = "--retry" in args
    only = None
    if "--only" in args:
        i = args.index("--only"); only = args[i + 1]; del args[i:i + 2]
    args = [a for a in args if a not in ("--force", "--retry")]

    for d in (PA_DIR, OSV_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)

    targets = args or sorted(d.name for d in PROJECTS.iterdir()
                             if d.is_dir() and "__" in d.name and not d.name.startswith("_"))
    scanners = [s for s in ("pip-audit", "osv-scanner") if only in (None, s)]
    runners = {"pip-audit": run_pip_audit, "osv-scanner": run_osv}

    cp = load_checkpoint()
    log(f"=== run start: {len(targets)} projects x {scanners} "
        f"(force={force}, retry={retry}) ===")

    for project in targets:
        pdir = PROJECTS / project
        if not pdir.is_dir():
            log(f"!! {project}: missing project dir, skip"); continue
        cp.setdefault(project, {})
        for scanner in scanners:
            prev = cp[project].get(scanner, {})
            done = prev.get("status") in OK_STATES
            if done and not force and not retry:
                log(f"-- {project} / {scanner}: skip (checkpoint={prev.get('status')})")
                continue
            if retry and done and not force:
                log(f"-- {project} / {scanner}: skip (already {prev.get('status')})")
                continue
            t0 = time.time()
            res = runners[scanner](project, pdir)
            res["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
            res["secs"] = round(time.time() - t0, 1)
            cp[project][scanner] = res
            save_checkpoint(cp)  # incremental: crash-safe
            log(f">> {project} / {scanner}: {res.get('status')} "
                f"vulns={res.get('vulns','-')} pkgs={res.get('vuln_pkgs','-')} "
                f"({res.get('secs')}s)")

    # aggregate
    rows = []
    for project in sorted(cp):
        pa = cp[project].get("pip-audit", {})
        ov = cp[project].get("osv-scanner", {})
        rows.append({
            "project": project,
            "pip_audit_status": pa.get("status", "-"),
            "pip_audit_scanned": pa.get("scanned", ""),
            "pip_audit_vulns": pa.get("vulns", ""),
            "pip_audit_vuln_pkgs": pa.get("vuln_pkgs", ""),
            "pip_audit_skipped": len(pa.get("skipped", []) or []),
            "osv_status": ov.get("status", "-"),
            "osv_scanned": ov.get("scanned", ""),
            "osv_vulns": ov.get("vulns", ""),
            "osv_vuln_pkgs": ov.get("vuln_pkgs", ""),
        })
    cols = ["project", "pip_audit_status", "pip_audit_scanned", "pip_audit_vulns",
            "pip_audit_vuln_pkgs", "pip_audit_skipped",
            "osv_status", "osv_scanned", "osv_vulns", "osv_vuln_pkgs"]
    with (SCANS / "vuln_summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader(); w.writerows(rows)

    tot_pa = sum(int(r["pip_audit_vulns"] or 0) for r in rows)
    tot_ov = sum(int(r["osv_vulns"] or 0) for r in rows)
    log(f"=== done. pip-audit total vulns={tot_pa}, osv total vulns={tot_ov} "
        f"-> {SCANS/'vuln_summary.csv'} ===")


if __name__ == "__main__":
    main()
