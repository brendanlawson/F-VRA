from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from f_vra.core.models import AnalysisFingerprint, LibrarySummary, PackageIdentity, PackageSummaryArtifact
from f_vra.analysis.package.summary import apply_public_api_aliases, filter_verdict_affecting_warnings


def edge_rows(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = report.get("final_edges_detail") or report.get("edges_detail") or []
    return [row for row in rows if row.get("caller") and row.get("callee")]


def summary_from_callgraph_report(report: Mapping[str, Any]) -> LibrarySummary:
    adjacency: dict[str, list[tuple[str, str]]] = {}
    callers: set[str] = set()
    for edge in edge_rows(report):
        caller = str(edge["caller"])
        callee = str(edge["callee"])
        callee_type = str(edge.get("callee_type", "internal"))
        callers.add(caller)
        adjacency.setdefault(caller, []).append((callee, callee_type))

    summary = LibrarySummary()
    for api in sorted(callers):
        queue = [api]
        visited = {api}
        paths = {api: [api]}
        inner: set[str] = set()
        outer: set[str] = set()
        while queue:
            node = queue.pop(0)
            for nxt, callee_type in adjacency.get(node, []):
                if callee_type == "external":
                    outer.add(nxt)
                    summary.outer_paths.setdefault(api, {}).setdefault(nxt, [*paths[node], nxt])
                    continue
                if nxt in visited:
                    continue
                visited.add(nxt)
                paths[nxt] = [*paths[node], nxt]
                inner.add(nxt)
                summary.inner_paths.setdefault(api, {}).setdefault(nxt, paths[nxt])
                queue.append(nxt)
        summary.inner_summary[api] = inner
        summary.outer_summary[api] = outer
    aliases = report.get("public_api_aliases", {})
    if isinstance(aliases, Mapping):
        root = str(
            report.get("normalized_name")
            or report.get("package")
            or Path(str(report.get("root", ""))).name
        ).replace("-", "_").lower()
        apply_public_api_aliases(summary, aliases, import_root=root)
    summary.analysis_warnings = filter_verdict_affecting_warnings({
        key: report.get(key, [])
        for key in ("candidate_edges", "unresolved_public_exports", "unresolved_calls")
        if report.get(key)
    })
    return summary


def package_identity_from_report(
    report: Mapping[str, Any],
    *,
    package: str | None = None,
    version: str | None = None,
) -> PackageIdentity:
    name = package or str(
        report.get("normalized_name")
        or report.get("package")
        or Path(str(report.get("root", "package"))).name
    )
    return PackageIdentity(
        name=name,
        normalized_name=str(report.get("normalized_name") or name).replace("_", "-").lower(),
        version=version or str(report.get("version") or ""),
    )


def package_summary_key(identity: PackageIdentity) -> str:
    return f"{identity.normalized_name or identity.name}=={identity.version}"


def package_summary_artifact_from_report(
    report: Mapping[str, Any],
    *,
    package: str | None = None,
    version: str | None = None,
    source_path: str = "",
) -> PackageSummaryArtifact:
    identity = package_identity_from_report(report, package=package, version=version)
    return PackageSummaryArtifact(
        package=identity,
        fingerprint=AnalysisFingerprint(),
        summary=summary_from_callgraph_report(report),
        source_path=str(report.get("root", "")),
        provenance={"source": "package_report", "path": source_path},
    )
