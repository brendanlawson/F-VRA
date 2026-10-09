from __future__ import annotations

from typing import Protocol

from f_vra.core.models import (
    PackageSummaryArtifact,
    ProjectGraphArtifact,
    ScanReport,
    VulnerabilityRecord,
)


class VulnerabilityRepository(Protocol):
    def get(self, cve_id: str) -> VulnerabilityRecord | None:
        ...

    def put(self, record: VulnerabilityRecord) -> None:
        ...

    def list(self) -> list[str]:
        ...


class PackageSummaryRepository(Protocol):
    def get(self, key: str) -> PackageSummaryArtifact | None:
        ...

    def put(self, key: str, artifact: PackageSummaryArtifact) -> None:
        ...

    def list(self) -> list[str]:
        ...


class ProjectArtifactStore(Protocol):
    def get(self, key: str) -> ProjectGraphArtifact | None:
        ...

    def put(self, key: str, artifact: ProjectGraphArtifact) -> None:
        ...


class ScanReportStore(Protocol):
    def get(self, scan_id: str) -> ScanReport | None:
        ...

    def put(self, report: ScanReport) -> None:
        ...

