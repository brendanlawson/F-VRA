"""Freeze and bind the three VF inputs used by RQ3."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from f_vra.evaluation.contracts import VFAnchor
from f_vra.evaluation.environment import PROBE
from f_vra.evaluation.io import read_parquet, write_json, write_parquet


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _workbook_localizer(workbook: Path) -> dict[tuple[str, str], list[str]]:
    from openpyxl import load_workbook

    result: dict[tuple[str, str], list[str]] = {}
    book = load_workbook(workbook, read_only=True, data_only=True)
    try:
        sheet = book["manual_annotation"]
        rows = sheet.values
        headings = next(rows)
        columns = {str(value): index for index, value in enumerate(headings)}
        for row in rows:
            project = str(row[columns["project"]] or "").strip()
            cve = str(row[columns["cve"]] or "").strip()
            raw = str(row[columns["auto_vf"]] or "")
            names = []
            for item in raw.split(";"):
                name = re.sub(r"\s*\[[^]]+\]\s*$", "", item).strip()
                if name:
                    names.append(name)
            result[(project, cve)] = names
    finally:
        book.close()
    return result


def _patch_candidates(path: Path) -> dict[tuple[str, str], list[str]]:
    result: dict[tuple[str, str], list[str]] = {}
    for row in _jsonl(path):
        key = (str(row.get("advisory_id") or row.get("cve_id") or ""), canonicalize_name(str(row.get("package") or "")))
        candidates = row.get("candidates") or {}
        values = (candidates.get("patch_modified") or []) if isinstance(candidates, dict) else (candidates or [])
        names = []
        for item in values or []:
            name = str(item.get("qualified_name") or "").strip()
            if name and not name.endswith(".__module__"):
                names.append(name)
        result[key] = sorted(set(names))
    return result


def _probe_env(image: str, requests: list[dict[str, str]]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="f_vra-vf-") as temporary:
        root = Path(temporary)
        request_path = root / "requests.json"
        output_path = root / "probe.json"
        write_json(request_path, requests)
        command = [
            "docker", "run", "--rm", "--network=none", "--cpus=8", "--memory=16g",
            "-v", f"{PROBE.resolve().as_posix()}:/probe.py:ro",
            "-v", f"{request_path.resolve().as_posix()}:/requests.json:ro",
            image, "sh", "-c", 'exec "$F_VRA_TARGET_PYTHON" /probe.py /requests.json',
        ]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout)[-3000:])
        output_path.write_text(result.stdout, encoding="utf-8")
        return json.loads(output_path.read_text(encoding="utf-8"))


def build_vf_variants(dataset_dir: Path, workbook: Path, patch_source: Path, output: Path) -> dict[str, Any]:
    queries = read_parquet(dataset_dir / "queries.parquet")
    packages = {row["package_id"]: row for row in read_parquet(dataset_dir / "packages.parquet")}
    environments = {row["env_id"]: row for row in read_parquet(dataset_dir / "environments.parquet")}
    localizer = _workbook_localizer(workbook)
    patch = _patch_candidates(patch_source)
    requested: dict[str, list[dict[str, str]]] = defaultdict(list)
    names_by_query: dict[tuple[str, str], list[str]] = {}
    for query in queries:
        distribution = canonicalize_name(str(query["affected_distribution"]))
        selections = {
            "V1_PATCH": patch.get((str(query["cve_id"]), distribution), []),
            "V2_LOCALIZER": localizer.get((str(query["project_id"]), str(query["cve_id"])), []),
        }
        for variant, names in selections.items():
            names_by_query[(str(query["query_id"]), variant)] = names
            requested[str(query["env_id"])].extend({"distribution": distribution, "qualified_name": name} for name in names)
    probe_by_env = {}
    for env_id, requests in requested.items():
        unique = list({(row["distribution"], row["qualified_name"]): row for row in requests}.values())
        probe_by_env[env_id] = _probe_env(str(environments[env_id]["docker_image_digest"]), unique)
    rows = []
    audit = []
    for query in queries:
        query_id = str(query["query_id"])
        package = packages[str(query["affected_package_id"])]
        distribution = canonicalize_name(str(query["affected_distribution"]))
        rows.append({"query_id": query_id, "variant": "V0_ORACLE", "vf_set": query.get("vf_set") or []})
        for variant in ("V1_PATCH", "V2_LOCALIZER"):
            anchors = []
            statuses = []
            for qualified in names_by_query.get((query_id, variant), []):
                bound = probe_by_env[str(query["env_id"])]["anchors"].get(distribution + "|" + qualified, {})
                status = str(bound.get("status") or "UNKNOWN_VF_MISMATCH")
                statuses.append(status)
                if status == "BOUND":
                    anchors.append(VFAnchor(
                        package_id=str(package["package_id"]), module=str(bound["module"]),
                        qualified_name=qualified, file=str(bound["file"]),
                        start_line=int(bound["start_line"]), end_line=int(bound["end_line"]),
                        function_hash=str(bound["function_hash"]), provenance=variant.lower(),
                    ).model_dump(mode="json"))
            rows.append({"query_id": query_id, "variant": variant, "vf_set": anchors})
            audit.append({
                "query_id": query_id, "project_id": query["project_id"], "cve_id": query["cve_id"],
                "variant": variant, "requested": len(names_by_query.get((query_id, variant), [])),
                "bound": len(anchors), "status": "BOUND" if anchors and len(anchors) == len(statuses) else "UNKNOWN_VF_MISMATCH",
                "binding_statuses": statuses,
            })
    write_parquet(output, rows)
    audit_path = output.with_name(output.stem + "_audit.parquet")
    write_parquet(audit_path, audit)
    summary = {
        "queries": len(queries), "rows": len(rows),
        "variant_counts": {variant: sum(row["variant"] == variant for row in rows) for variant in ("V0_ORACLE", "V1_PATCH", "V2_LOCALIZER")},
        "fully_bound": sum(row["status"] == "BOUND" for row in audit),
        "audit": str(audit_path),
    }
    write_json(output.with_suffix(".summary.json"), summary)
    return summary
