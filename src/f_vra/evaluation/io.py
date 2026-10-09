"""Stable Parquet/JSON persistence shared by every experiment."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_parquet(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq

    records = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not records:
        # Keep a readable file for empty audit/event populations.
        records = [{"_empty": True}]
    else:
        fields = sorted({field for record in records for field in record})
        records = [{field: record.get(field) for field in fields} for record in records]
    temporary = path.with_suffix(path.suffix + ".tmp")
    pq.write_table(pa.Table.from_pylist(records), temporary, compression="zstd")
    temporary.replace(path)


def read_parquet(path: Path) -> list[dict[str, Any]]:
    import pyarrow.parquet as pq

    return [row for row in pq.read_table(path).to_pylist() if not row.get("_empty")]
