"""Immutable, content-addressed contracts for the research harness."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def digest(value: Any) -> str:
    """Hash a portable JSON value, never a local path or Python repr."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=True)
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Decision(str, Enum):
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"


class UnknownReason(str, Enum):
    SOURCE = "UNKNOWN_SOURCE"
    NATIVE_BOUNDARY = "UNKNOWN_NATIVE_BOUNDARY"
    DYNAMIC_BOUNDARY = "UNKNOWN_DYNAMIC_BOUNDARY"
    PARSE = "UNKNOWN_PARSE_BOUNDARY"
    BUDGET = "UNKNOWN_BUDGET"
    TIMEOUT = "UNKNOWN_TIMEOUT"
    VF_MISMATCH = "UNKNOWN_VF_MISMATCH"
    MAPPING = "UNKNOWN_PACKAGE_MAPPING"
    BACKEND = "UNKNOWN_BACKEND"
    UNRESOLVED = "UNKNOWN_UNRESOLVED_FRONTIER"


class ProjectSnapshot(FrozenModel):
    project_id: str
    git_url: str
    commit_sha: str
    source_hash: str

    @property
    def snapshot_id(self) -> str:
        return digest(self)


class EnvironmentSnapshot(FrozenModel):
    project_snapshot_id: str
    lockfile_type: str
    lockfile_hash: str
    python_version: str
    platform: str
    docker_image_digest: str
    installed_distribution_manifest_hash: str
    jarvis_python_version: str = "3.8"
    generated_lock: bool = False
    resolver_version: str = ""
    resolution_date: str = ""

    @property
    def env_id(self) -> str:
        # The time of an otherwise identical rebuild is provenance, not identity.
        return digest(self.model_dump(exclude={"resolution_date"}))


class PackageID(FrozenModel):
    distribution: str
    version: str
    source_hash: str
    python_abi: str
    platform_tag: str
    wheel_hash: str = ""
    backend_version: str
    ast_adapter_version: str
    analysis_config_hash: str

    @property
    def package_id(self) -> str:
        return digest(self)


class VFAnchor(FrozenModel):
    package_id: str
    module: str
    qualified_name: str
    file: str = ""
    start_line: int = 0
    end_line: int = 0
    function_hash: str = ""
    provenance: str

    @property
    def vf_id(self) -> str:
        return digest(self)


class ImpactQuery(FrozenModel):
    project_snapshot_id: str
    env_id: str
    cve_id: str
    affected_package_id: str
    dependency_type: str
    vf_set: tuple[VFAnchor, ...] = ()
    eligibility_reason: str = "eligible"

    @property
    def query_id(self) -> str:
        return digest((self.project_snapshot_id, self.env_id, self.cve_id))


class OracleLabel(FrozenModel):
    candidate_id: str
    query_id: str = ""
    decision: Decision
    reason: str = ""
    witness: str = ""
    annotator: str = ""
    source_workbook_hash: str = ""
    review_status: str = "pending_review"
    review_reason: str = ""
    reviewer: str = ""
    reviewed_at: str = ""


class QueryOutcome(FrozenModel):
    query_id: str
    strategy: str
    decision: Decision
    unknown_reason: UnknownReason | None = None
    witnesses: tuple[tuple[str, ...], ...] = ()
    wall_clock_ms: float = 0.0
    cpu_time_ms: float = 0.0
    peak_rss_mb: float = 0.0
    functions_analyzed: int = 0
    unique_functions_analyzed: int = 0
    call_edges_materialized: int = 0
    fragments_built: int = 0
    fragments_reused: int = 0
    artifact_bytes_read: int = 0
    artifact_bytes_written: int = 0
    cache_lookup_count: int = 0
    cache_hit_count: int = 0
    witness_length: int = 0
    details: dict[str, Any] = Field(default_factory=dict)
