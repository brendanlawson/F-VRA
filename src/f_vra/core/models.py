from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


SCHEMA_VERSION = "1"


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VersionedContractModel(ContractModel):
    schema_version: str = SCHEMA_VERSION

    @model_validator(mode="after")
    def _check_schema_version(self):
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported schema_version={self.schema_version!r}; "
                f"expected {SCHEMA_VERSION!r}"
            )
        return self


class Verdict(str, Enum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    POTENTIALLY_REACHABLE = "potentially_reachable"
    UNKNOWN = "unknown"

    # Display aliases.
    AFFECTED = "reachable"
    NOT_AFFECTED = "not_reachable"


class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    sarif = "sarif"


class EntryPointType(str, Enum):
    MAIN = "main"
    CLI = "cli"
    WEB = "web"
    TEST = "test"
    UNKNOWN = "unknown"


@dataclass(eq=False)
class FunctionNode:
    file_path: str
    function_name: str
    qualified_name: str = ""
    line_number: int = 0
    module: str = ""
    scope: str = ""
    signature: str = ""
    arity: int = 0
    source_snippet: str = ""
    entry_type: EntryPointType = EntryPointType.UNKNOWN
    is_external: bool = False

    def __hash__(self) -> int:
        return hash((str(Path(self.file_path)).replace("\\", "/"), self.function_name, self.is_external))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FunctionNode):
            return False
        return (
            str(Path(self.file_path)).replace("\\", "/"),
            self.function_name,
            self.is_external,
        ) == (
            str(Path(other.file_path)).replace("\\", "/"),
            other.function_name,
            other.is_external,
        )


@dataclass(eq=False)
class ExternalNode(FunctionNode):
    target_module: str = ""
    target_name: str = ""
    is_external: bool = True

    @property
    def identity_string(self) -> str:
        return ".".join(part for part in (self.target_module, self.target_name) if part)

    def __hash__(self) -> int:
        return hash((self.target_module, self.target_name, True))

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, ExternalNode)
            and self.target_module == other.target_module
            and self.target_name == other.target_name
        )


@dataclass
class CallEdge:
    caller: FunctionNode
    callee: FunctionNode
    edge_type: str = "confirmed_static"
    confidence: float = 1.0
    resolver: str = "static"
    reason: str = ""
    call_expr: str = ""
    line_number: int = 0


@dataclass
class UnresolvedCall:
    caller: str
    file_path: str
    line_number: int
    call_expr: str
    call_name: str = ""
    receiver: str = ""
    arity: int = 0
    reason: str = "static resolver found no target"


@dataclass
class CandidateEdge:
    caller: str
    callee: str
    file_path: str
    line_number: int
    call_expr: str
    confidence: float = 0.0
    resolver: str = "coarse_name_arity"
    status: str = "candidate"
    reason: str = ""
    arity: int = 0
    receiver: str = ""
    caller_signature: str = ""
    callee_signature: str = ""
    caller_source: str = ""
    callee_source: str = ""


@dataclass
class CallGraph:
    nodes: set[FunctionNode] = field(default_factory=set)
    edges: list[CallEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_node(self, node: FunctionNode) -> bool:
        before = len(self.nodes)
        self.nodes.add(node)
        return len(self.nodes) != before

    @property
    def internal_nodes(self) -> set[FunctionNode]:
        """First-party functions/methods represented in this graph."""
        return {node for node in self.nodes if not node.is_external}

    @property
    def external_nodes(self) -> set[ExternalNode]:
        """Boundary targets outside the analyzed root."""
        return {node for node in self.nodes if isinstance(node, ExternalNode)}

    @property
    def internal_edges(self) -> list[CallEdge]:
        """Edges whose caller and callee are both first-party nodes."""
        return [
            edge for edge in self.edges
            if not edge.caller.is_external and not edge.callee.is_external
        ]

    @property
    def external_edges(self) -> list[CallEdge]:
        """Edges that cross from analyzed code into a third-party/stdlib target."""
        return [edge for edge in self.edges if edge.callee.is_external]


class LibrarySummary(VersionedContractModel):
    inner_summary: dict[str, set[str]] = Field(default_factory=dict)
    outer_summary: dict[str, set[str]] = Field(default_factory=dict)
    inner_paths: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    outer_paths: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    analysis_warnings: dict[str, Any] = Field(default_factory=dict)
    api_aliases: dict[str, str] = Field(default_factory=dict)
    symbol_table: dict[str, dict[str, Any]] = Field(default_factory=dict)
    export_table: dict[str, dict[str, Any]] = Field(default_factory=dict)
    alias_table: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    outer_edge_details: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    diagnostics: dict[str, Any] = Field(default_factory=dict)


@dataclass
class ReachabilityPath:
    project_api: str
    tpl_chain: list[str]
    vulnerable_target: str
    used_summaries: list[str] = field(default_factory=list)


@dataclass
class QueryReport:
    is_vulnerable: bool
    paths: list[ReachabilityPath] = field(default_factory=list)
    unresolved_targets: list[str] = field(default_factory=list)
    unresolved_frontier: list[str] = field(default_factory=list)
    used_summaries: list[str] = field(default_factory=list)


class Evidence(ContractModel):
    source: str
    detail: str
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnerableEntity(ContractModel):
    package: str
    name: str
    entity_type: str = "function"
    role: str = "sink"
    confidence: float = 0.0
    evidence: list[Evidence] = Field(default_factory=list)


class VulnerabilityRecord(VersionedContractModel):
    cve_id: str
    package: str
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    entities: list[VulnerableEntity] = Field(default_factory=list)


class PackageIdentity(ContractModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    version: str = ""
    normalized_name: str = ""
    python_version: str = ""


class ProjectIdentity(ContractModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    root: str
    fingerprint: str


class AnalysisFingerprint(ContractModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scanner_version: str = "0.3.0"
    config_hash: str = "default"
    python_version: str = ""


class DependencyRecord(ContractModel):
    name: str
    normalized_name: str
    version: str = ""
    specifier: str = ""
    ecosystem: str = "pypi"
    direct: bool = False
    dev: bool = False
    source_file: str = ""
    source_type: str = ""
    # Lockfile identity dimensions.  Keeping these fields prevents a
    # platform/index-specific record from being flattened into a package-name
    # only record during dependency graph construction.
    marker: str = ""
    source: str = ""
    source_path: str = ""
    dependencies: list[str] = Field(default_factory=list)
    dependency_edges: list[dict[str, str]] = Field(default_factory=list)
    purl: str = ""


class DependencyGraphArtifact(VersionedContractModel):
    project: ProjectIdentity
    fingerprint: AnalysisFingerprint = Field(default_factory=AnalysisFingerprint)
    source_files: list[str] = Field(default_factory=list)
    resolver: str = "f_vra-static"
    dependencies: list[DependencyRecord] = Field(default_factory=list)
    analysis_warnings: dict[str, Any] = Field(default_factory=dict)


class ProjectGraphArtifact(VersionedContractModel):
    project: ProjectIdentity
    fingerprint: AnalysisFingerprint = Field(default_factory=AnalysisFingerprint)
    entry_points: list[str] = Field(default_factory=list)
    usage_index: list[str] = Field(default_factory=list)
    graph: dict[str, Any] = Field(default_factory=dict)
    analysis_warnings: dict[str, Any] = Field(default_factory=dict)


class PackageSummaryArtifact(VersionedContractModel):
    package: PackageIdentity
    fingerprint: AnalysisFingerprint = Field(default_factory=AnalysisFingerprint)
    summary: LibrarySummary = Field(default_factory=LibrarySummary)
    source_path: str = ""
    provenance: dict[str, Any] = Field(default_factory=dict)


class ScanTarget(ContractModel):
    type: str = "git"
    repo_url: str = ""
    repo: str = ""
    branch: str = ""
    commit_sha: str = ""
    project_id: str = ""
    project_name: str = ""


class ScanSummary(ContractModel):
    dependency_count: int = 0
    finding_count: int = 0
    reachable: int = 0
    potentially_reachable: int = 0
    not_reachable: int = 0
    unknown: int = 0


class DependencyInventoryItem(ContractModel):
    ecosystem: str = "pypi"
    name: str = ""
    normalized_name: str = ""
    version: str = ""
    purl: str = ""
    direct: bool = False
    dev: bool = False
    manifest: str = ""
    dependency_path: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)


class AdvisoryOutput(ContractModel):
    id: str
    aliases: list[str] = Field(default_factory=list)
    title: str = ""
    summary: str = ""
    severity: str = "Medium"
    score: float = 0.0
    cvss: dict[str, Any] | None = None
    cwe: list[str] = Field(default_factory=list)
    references: list[dict[str, Any]] = Field(default_factory=list)
    published_at: str = ""
    modified_at: str = ""


class RemediationOutput(ContractModel):
    upgrade_to: str = ""
    fixed_versions: list[str] = Field(default_factory=list)
    is_upgradable: bool = False
    is_patchable: bool = False


class PackageOutput(ContractModel):
    ecosystem: str = "pypi"
    name: str = ""
    normalized_name: str = ""
    version: str = ""
    purl: str = ""
    affected_ranges: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    direct: bool = False
    dev: bool = False
    dependency_path: list[str] = Field(default_factory=list)


class VulnerableEntityOutput(ContractModel):
    qualified_name: str = ""
    entity_type: str = "function"
    role: str = "sink"
    confidence: float = 0.0
    source: str = ""
    evidence: Any = Field(default_factory=dict)


class PathNodeOutput(ContractModel):
    name: str
    kind: str = "application"
    package: str = ""
    file: str = ""
    line: int = 0
    call_expr: str = ""
    source_snippet: str = ""
    source_start_line: int = 0
    confidence: float = 1.0


class PathOutput(ContractModel):
    project_api: str = ""
    vulnerable_target: str = ""
    path: list[str] = Field(default_factory=list)
    used_summaries: list[str] = Field(default_factory=list)
    nodes: list[PathNodeOutput] = Field(default_factory=list)
    warnings: list[dict[str, Any]] = Field(default_factory=list)


class ReachabilityOutput(ContractModel):
    verdict: Verdict = Verdict.UNKNOWN
    path_count: int = 0
    evidence_status: str = "unavailable"
    reason: str = ""
    paths: list[PathOutput] = Field(default_factory=list)
    used_summaries: list[str] = Field(default_factory=list)
    loaded_summaries: list[str] = Field(default_factory=list)
    unresolved: dict[str, Any] = Field(default_factory=dict)
    warnings: dict[str, Any] = Field(default_factory=dict)
    query_time_ms: float = 0.0


class ArtifactSummaryOutput(ContractModel):
    project_call_graph: dict[str, Any] = Field(default_factory=dict)
    package_summary: dict[str, Any] = Field(default_factory=dict)
    package_call_graph: dict[str, Any] = Field(default_factory=dict)


class ScanFindingOutput(ContractModel):
    id: str
    type: str = "vulnerability_reachability"
    advisory: AdvisoryOutput
    package: PackageOutput
    vulnerable_entity: VulnerableEntityOutput = Field(default_factory=VulnerableEntityOutput)
    reachability: ReachabilityOutput
    locations: list[dict[str, Any]] = Field(default_factory=list)
    remediation: RemediationOutput = Field(default_factory=RemediationOutput)
    artifacts: ArtifactSummaryOutput = Field(default_factory=ArtifactSummaryOutput)
    project: dict[str, Any] = Field(default_factory=dict)


class FVRAScanReport(VersionedContractModel):
    schema_version: str = "f_vra.scan.v1"
    tool: dict[str, Any] = Field(default_factory=lambda: {"name": "f_vra", "version": "0.3.0"})
    scan: dict[str, Any] = Field(default_factory=dict)
    target: ScanTarget = Field(default_factory=ScanTarget)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    dependency_inventory: list[DependencyInventoryItem] = Field(default_factory=list)
    findings: list[ScanFindingOutput] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_schema_version(self):
        if self.schema_version != "f_vra.scan.v1":
            raise ValueError("unsupported scan report schema version")
        return self


class ScanReport(VersionedContractModel):
    scan_id: str
    cve_id: str
    project: ProjectIdentity
    verdict: Verdict = Verdict.UNKNOWN
    vulnerable_targets: list[str] = Field(default_factory=list)
    hit_set: list[str] = Field(default_factory=list)
    paths: list[dict[str, Any]] = Field(default_factory=list)
    unresolved_targets: list[str] = Field(default_factory=list)
    loaded_summaries: list[str] = Field(default_factory=list)
    query_time_ms: float = 0.0


@dataclass
class IndexResult:
    package: str
    version: str
    functions: int = 0
    api_count: int = 0
    elapsed_s: float = 0.0
    cached: bool = False


@dataclass
class LocalizeResult:
    cve_id: str
    package: str
    vf: str = ""
    score: float = 0.0
    mode: str = "unknown"
    candidates: list[str] = field(default_factory=list)
    cached: bool = False


@dataclass
class ScanResult:
    cve_id: str
    project: Path
    verdict: Verdict = Verdict.UNKNOWN
    vf: str = ""
    entry_points: list[str] = field(default_factory=list)
    hit_set: list[str] = field(default_factory=list)
    call_chain: list[str] = field(default_factory=list)
    query_time_ms: float = 0.0
    llm_invoked: bool = False
