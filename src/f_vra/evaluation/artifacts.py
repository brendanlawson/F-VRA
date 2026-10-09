"""Content-validated package fragments; import roots are never identities."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from f_vra.evaluation.contracts import digest
from f_vra.evaluation.io import write_json


FRAGMENT_SCHEMA_VERSION = "1"


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    @staticmethod
    def compatibility_key(package_id: str, root: str) -> str:
        return digest({"package_id": package_id, "root": root, "fragment_schema_version": FRAGMENT_SCHEMA_VERSION})

    def _path(self, namespace: str, key: str) -> Path:
        return self.root / namespace / key[:2] / f"{key}.json"

    def read(self, namespace: str, package_id: str, root: str) -> tuple[dict[str, Any] | None, str, int]:
        key = self.compatibility_key(package_id, root)
        path = self._path(namespace, key)
        if not path.is_file():
            return None, "MISS", 0
        size = path.stat().st_size
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None, "CORRUPT_ARTIFACT", size
        expected = {"package_id": package_id, "root": root, "schema_version": FRAGMENT_SCHEMA_VERSION, "compatibility_key": key}
        if any(payload.get(field) != value for field, value in expected.items()):
            return None, "COMPATIBILITY_MISMATCH", size
        fragment = payload.get("fragment")
        if not isinstance(fragment, dict) or digest(fragment) != payload.get("content_hash"):
            return None, "CONTENT_HASH_MISMATCH", size
        return fragment, "HIT", size

    def write(self, namespace: str, package_id: str, root: str, fragment: dict[str, Any]) -> int:
        key = self.compatibility_key(package_id, root)
        payload = {
            "package_id": package_id, "root": root, "schema_version": FRAGMENT_SCHEMA_VERSION,
            "compatibility_key": key, "content_hash": digest(fragment), "fragment": fragment,
        }
        path = self._path(namespace, key)
        write_json(path, payload)
        return path.stat().st_size
