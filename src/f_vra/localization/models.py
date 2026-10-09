from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal

LocalizationMode = Literal["PATCH_PRESENT", "PATCH_ABSENT"]
MetadataSource = Literal["OSV", "NVD", "GitHub", "manual", "unknown"]


@dataclass
class LocalizationRequest:
    repository_path: Path | None = None
    cve_id: str | None = None
    cve_description: str | None = None
    cwe_id: str | None = None
    patch_path: Path | None = None
    auto_resolve_patch: bool = False
    top_k: int = 20
    use_llm: bool = False
    use_rerank: bool | None = None
    rerank_model: str | None = None
    use_embeddings: bool = True
    candidate_pool_size: int = 100
    tracker_max_depth: int = 2
    cve_repeat: int = 5
    swiss_rounds: int = 8
    finalists: int = 20
    pairwise: bool = False
    pairwise_model: str | None = None
    extract_entities: bool = False
    entity_model: str | None = None
    progress_callback: Callable[[str], None] | None = field(
        default=None,
        repr=False,
        compare=False,
    )


@dataclass
class FunctionInfo:
    function_name: str
    qualname: str
    file_path: str
    start_line: int
    end_line: int
    source: str
    docstring: str = ""
    calls: set[str] = field(default_factory=set)
    referenced_names: set[str] = field(default_factory=set)
    assigned_names: set[str] = field(default_factory=set)
    parameter_names: set[str] = field(default_factory=set)
    local_types: dict[str, str] = field(default_factory=dict)
    decorators: list[str] = field(default_factory=list)
    is_async: bool = False

    @property
    def identity(self) -> str:
        return f"{self.file_path}:{self.qualname}"


@dataclass
class VulnerableFunctionCandidate:
    rank: int
    score: float
    confidence: float
    function_name: str
    qualname: str
    file_path: str
    start_line: int
    end_line: int
    source_excerpt: str
    why_this_may_be_vulnerable: str
    evidence_used: list[str]


@dataclass
class LocalizationReport:
    cve_id: str | None
    cve_description: str
    cwe_id: str | None
    repository_path: str
    mode: LocalizationMode
    patch_source: str | None
    metadata_source: MetadataSource
    candidates: list[VulnerableFunctionCandidate]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
