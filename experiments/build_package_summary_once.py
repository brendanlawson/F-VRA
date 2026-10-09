from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from f_vra.reachability.service import _build_package_summary  # noqa: E402


def _json_default(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build one installed package summary and write JSON payload.")
    parser.add_argument("root")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    started = time.perf_counter()
    payload: dict[str, Any]
    try:
        built = _build_package_summary(args.root)
    except Exception as exc:
        payload = {
            "summary": None,
            "status": {
                "root": args.root,
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_s": round(time.perf_counter() - started, 3),
            },
        }
    else:
        if built is None:
            payload = {
                "summary": None,
                "status": {
                    "root": args.root,
                    "status": "missing_source",
                    "elapsed_s": round(time.perf_counter() - started, 3),
                },
            }
        else:
            key, artifact = built
            payload = {
                "summary": artifact.summary,
                "status": {
                    "root": args.root,
                    "status": "built",
                    "cache_key": key,
                    "package": artifact.package.model_dump(mode="json"),
                    "source_path": artifact.source_path,
                    "summary_counts": {
                        "inner_keys": len(artifact.summary.inner_summary),
                        "outer_keys": len(artifact.summary.outer_summary),
                        "outer_targets": sum(len(values) for values in artifact.summary.outer_summary.values()),
                    },
                    "elapsed_s": round(time.perf_counter() - started, 3),
                },
            }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")
    return 0 if payload["status"]["status"] in {"built", "missing_source"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
