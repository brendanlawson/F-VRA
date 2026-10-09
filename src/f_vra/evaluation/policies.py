"""The four comparable materialization and reuse policies."""

from __future__ import annotations

from typing import Any, Callable

from f_vra.evaluation.artifacts import ArtifactStore


BuildFragment = Callable[[], dict[str, Any]]


class ArtifactPolicy:
    name = "base"

    def __init__(self, store: ArtifactStore) -> None:
        self.store = store
        self.events: list[dict[str, Any]] = []

    def namespace(self, project_snapshot_id: str, query_id: str) -> str:
        raise NotImplementedError

    def get_or_build(self, *, package_id: str, root: str, project_snapshot_id: str, query_id: str, build: BuildFragment, precompute: bool = False) -> tuple[dict[str, Any], bool]:
        namespace = self.namespace(project_snapshot_id, query_id)
        fragment, status, read_bytes = self.store.read(namespace, package_id, root)
        event = {
            "query_id": query_id, "package_id": package_id, "root": root,
            "namespace": namespace, "cache_lookup_count": 1,
            "artifact_bytes_read": read_bytes, "cache_status": status,
            "precomputation": precompute,
        }
        if fragment is not None:
            event.update({"event": "ARTIFACT_HIT", "cache_hit_count": 1, "fragments_reused": 1})
            self.events.append(event)
            return fragment, True
        if status != "MISS":
            event["reuse_rejected_reason"] = status
        fragment = build()
        written = self.store.write(namespace, package_id, root, fragment)
        event.update({
            "event": "FRAGMENT_BUILD", "artifact_bytes_written": written,
            "fragments_built": 1, "cache_hit_count": 0,
            "functions_analyzed": fragment.get("functions_analyzed", 0),
            "unique_functions_analyzed": fragment.get("unique_functions_analyzed", 0),
            "analyzed_functions": fragment.get("analyzed_functions", []),
            "call_edges_materialized": fragment.get("call_edges_materialized", 0),
            "wall_clock_ms": fragment.get("wall_clock_ms", 0.0),
            "cpu_time_ms": fragment.get("cpu_time_ms", 0.0),
            "peak_rss_mb": fragment.get("peak_rss_mb", 0.0),
        })
        self.events.append(event)
        return fragment, False


class FreshPolicy(ArtifactPolicy):
    name = "fresh"

    def namespace(self, project_snapshot_id: str, query_id: str) -> str:
        return f"fresh/{query_id}"


class ProjectLocalPolicy(ArtifactPolicy):
    name = "project_local"

    def namespace(self, project_snapshot_id: str, query_id: str) -> str:
        return f"project/{project_snapshot_id}"


class EagerSharedPolicy(ArtifactPolicy):
    name = "eager_shared"

    def namespace(self, project_snapshot_id: str, query_id: str) -> str:
        return "global"


class ProgressiveSharedPolicy(ArtifactPolicy):
    name = "progressive_shared"

    def namespace(self, project_snapshot_id: str, query_id: str) -> str:
        return "global"


POLICIES = {policy.name: policy for policy in (FreshPolicy, ProjectLocalPolicy, EagerSharedPolicy, ProgressiveSharedPolicy)}
