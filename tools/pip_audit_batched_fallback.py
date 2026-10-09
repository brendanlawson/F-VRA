#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCANS = Path(os.getenv("F_VRA_LEGACY_SCA_ROOT", ROOT / "data" / "_scans"))
INV = Path(os.getenv("F_VRA_PIP_AUDIT_FALLBACK_INV", SCANS / "snyk" / "inventory"))
OUT = SCANS / "pip-audit-fallback"
LOGS = SCANS / "logs"
SUMMARY = OUT / "summary.csv"

PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^ ;\\]+)")
OS_EXCLUDE_RE = re.compile(
    r"^(pyobjc(?:-.+)?|pywin32|pypiwin32|win32-setctime|winrt(?:-.+)?|comtypes|wmi|pycaw|"
    r"pyreadline3|windows-curses|pyobjc-framework-.+)$",
    re.I,
)
HEAVY_EXCLUDE_RE = re.compile(
    r"^(nvidia[-_].*|torch|torchvision|torchaudio|triton|tensorflow.*|jax|jaxlib|"
    r"onnxruntime.*|llama-cpp-python|chroma-hnswlib|bitsandbytes|flash[-_]attn.*)$",
    re.I,
)


def run(cmd: list[str], timeout: int, log: Path) -> subprocess.CompletedProcess[str] | None:
    with log.open("a", encoding="utf-8") as f:
        f.write("$ " + " ".join(cmd) + "\n")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        with log.open("a", encoding="utf-8") as f:
            f.write(f"TIMEOUT after {timeout}s\n")
            f.write((e.stdout or "") if isinstance(e.stdout, str) else "")
            f.write((e.stderr or "") if isinstance(e.stderr, str) else "")
        return None
    with log.open("a", encoding="utf-8") as f:
        f.write(f"# exit={proc.returncode}\n")
        if proc.stdout:
            f.write("=== STDOUT ===\n" + proc.stdout + "\n")
        if proc.stderr:
            f.write("=== STDERR ===\n" + proc.stderr + "\n")
    return proc


def read_pins(project: str) -> tuple[list[str], list[str]]:
    req = INV / project / "requirements.pinned.txt"
    if not req.exists():
        return [], ["missing requirements.pinned.txt"]
    pins: list[str] = []
    dropped: list[str] = []
    for raw in req.read_text(encoding="utf-8", errors="replace").splitlines():
        m = PIN_RE.match(raw.strip())
        if not m:
            continue
        name = m.group(1)
        pin = f"{name}=={m.group(2)}"
        if OS_EXCLUDE_RE.match(name):
            dropped.append(pin)
            continue
        pins.append(pin)
    return sorted(set(pins), key=str.lower), dropped


def chunks(items: list[str], size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def audit_batch(
    project: str,
    batch: list[str],
    batch_idx: int,
    timeout: int,
    log: Path,
    work_dir: Path,
) -> tuple[list[dict], list[str]]:
    req = work_dir / f"{project}.{batch_idx}.txt"
    out = work_dir / f"{project}.{batch_idx}.json"
    req.write_text("\n".join(batch) + "\n", encoding="utf-8")
    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(req),
        "--no-deps",
        "-s",
        "osv",
        "--progress-spinner",
        "off",
        "-f",
        "json",
        "-o",
        str(out),
    ]
    proc = run(cmd, timeout, log)
    if proc is None:
        return [], batch
    if out.exists():
        try:
            data = json.loads(out.read_text(encoding="utf-8-sig"))
            return data.get("dependencies", []), []
        except json.JSONDecodeError:
            pass
    if len(batch) == 1:
        return [], batch
    deps: list[dict] = []
    failed: list[str] = []
    for i, pin in enumerate(batch, start=1):
        d, f = audit_batch(project, [pin], batch_idx * 1000 + i, timeout, log, work_dir)
        deps.extend(d)
        failed.extend(f)
    return deps, failed


def merge_dependencies(deps: list[dict]) -> list[dict]:
    by_key: dict[tuple[str, str], dict] = {}
    for dep in deps:
        key = (dep.get("name", ""), dep.get("version", ""))
        if key not in by_key:
            by_key[key] = {"name": key[0], "version": key[1], "vulns": []}
        seen = {json.dumps(v, sort_keys=True) for v in by_key[key]["vulns"]}
        for vuln in dep.get("vulns", []) or []:
            marker = json.dumps(vuln, sort_keys=True)
            if marker not in seen:
                by_key[key]["vulns"].append(vuln)
                seen.add(marker)
    return list(by_key.values())


def run_project(project: str, batch_size: int, timeout: int) -> dict[str, str | int]:
    OUT.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    log = LOGS / f"{project}.pip-audit-fallback.log"
    log.write_text(f"# project={project}\n", encoding="utf-8")
    pins, dropped = read_pins(project)
    pins = [p for p in pins if not HEAVY_EXCLUDE_RE.match(p.split("==", 1)[0])]
    dropped.extend([p for p in read_pins(project)[0] if HEAVY_EXCLUDE_RE.match(p.split("==", 1)[0])])
    if not pins:
        return {"project": project, "status": "no-pins", "scanned": 0, "vulns": 0, "vuln_pkgs": 0, "failed": 0, "dropped": len(dropped)}

    all_deps: list[dict] = []
    failed: list[str] = []
    with tempfile.TemporaryDirectory(prefix=f"pa-fallback-{project}-") as tmp:
        work = Path(tmp)
        for idx, batch in enumerate(chunks(pins, batch_size), start=1):
            deps, bad = audit_batch(project, batch, idx, timeout, log, work)
            all_deps.extend(deps)
            failed.extend(bad)

    merged = merge_dependencies(all_deps)
    out_json = OUT / f"{project}.json"
    out_json.write_text(json.dumps({"dependencies": merged, "fixes": [], "fallback": {"failed": failed, "dropped": dropped}}, indent=2), encoding="utf-8")
    vuln_count = sum(len(dep.get("vulns", []) or []) for dep in merged)
    vuln_pkgs = sum(1 for dep in merged if dep.get("vulns"))
    status = "vulns" if vuln_count else "clean"
    if failed:
        status = "partial-vulns" if vuln_count else "partial-clean"
    return {
        "project": project,
        "status": status,
        "scanned": len(merged),
        "vulns": vuln_count,
        "vuln_pkgs": vuln_pkgs,
        "failed": len(failed),
        "dropped": len(dropped),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("projects", nargs="+")
    parser.add_argument("--batch-size", type=int, default=25)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    rows = [run_project(p, args.batch_size, args.timeout) for p in args.projects]
    existing = []
    if SUMMARY.exists():
        with SUMMARY.open(newline="", encoding="utf-8") as f:
            existing = [r for r in csv.DictReader(f) if r["project"] not in set(args.projects)]
    fields = ["project", "status", "scanned", "vulns", "vuln_pkgs", "failed", "dropped"]
    with SUMMARY.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(existing)
        w.writerows(rows)
    for row in rows:
        print(row)


if __name__ == "__main__":
    main()
