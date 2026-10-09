from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from f_vra.core.config import settings
from f_vra.core.models import PackageSummaryArtifact, VulnerabilityRecord

T = TypeVar("T", bound=BaseModel)


def _safe_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


class ServerFileDb:
    """File-backed server repository: SQLite metadata plus JSON payloads."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or (Path.home() / ".f_vra" / "server")
        self.db_path = self.root / "filedb.db"
        self.root.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    kind TEXT NOT NULL,
                    key TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    scanner_version TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    payload_path TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (kind, key)
                )
                """
            )

    def _put(self, kind: str, key: str, artifact: BaseModel, rel_path: Path) -> None:
        path = self.root / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
        now = time.time()
        schema_version = str(getattr(artifact, "schema_version", "1"))
        fingerprint = getattr(artifact, "fingerprint", None)
        scanner_version = str(getattr(fingerprint, "scanner_version", ""))
        config_hash = str(getattr(fingerprint, "config_hash", ""))
        with self._connect() as db:
            existing = db.execute(
                "SELECT created_at FROM artifacts WHERE kind = ? AND key = ?",
                (kind, key),
            ).fetchone()
            db.execute(
                """
                INSERT OR REPLACE INTO artifacts
                (kind, key, schema_version, scanner_version, config_hash, payload_path, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    kind,
                    key,
                    schema_version,
                    scanner_version,
                    config_hash,
                    rel_path.as_posix(),
                    existing[0] if existing else now,
                    now,
                ),
            )

    def _get(self, kind: str, key: str, model: type[T]) -> T | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT payload_path FROM artifacts WHERE kind = ? AND key = ?",
                (kind, key),
            ).fetchone()
        if row is None:
            return None
        path = self.root / row[0]
        if not path.exists():
            return None
        try:
            return model.model_validate(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, ValidationError):
            return None

    def put(self, record: VulnerabilityRecord) -> None:
        self.put_vulnerability(record)

    def get(self, cve_id: str) -> VulnerabilityRecord | None:
        return self.get_vulnerability(cve_id)

    def put_vulnerability(self, record: VulnerabilityRecord) -> None:
        self._put("vulnerability", record.cve_id, record, Path("vulnerabilities") / f"{_safe_key(record.cve_id)}.json")

    def get_vulnerability(self, cve_id: str) -> VulnerabilityRecord | None:
        return self._get("vulnerability", cve_id, VulnerabilityRecord)

    def put_package_summary(self, key: str, artifact: PackageSummaryArtifact) -> None:
        self._put("package-summary", key, artifact, Path("package-summaries") / f"{_safe_key(key)}.json")

    def get_package_summary(self, key: str) -> PackageSummaryArtifact | None:
        return self._get("package-summary", key, PackageSummaryArtifact)

    def list(self, kind: str = "vulnerability") -> list[str]:
        with self._connect() as db:
            return [
                row[0]
                for row in db.execute(
                    "SELECT key FROM artifacts WHERE kind = ? ORDER BY key",
                    (kind,),
                ).fetchall()
            ]


def default_server_filedb() -> ServerFileDb:
    return ServerFileDb(settings.server_store_dir)

