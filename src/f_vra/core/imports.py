from __future__ import annotations

import keyword
import re
from pathlib import Path
from typing import Any


IGNORED_IMPORT_ROOTS = {
    "__pycache__",
    "benchmark",
    "benchmarks",
    "build",
    "dist",
    "doc",
    "docs",
    "example",
    "examples",
    "script",
    "scripts",
    "test",
    "tests",
    "tool",
    "tools",
}


def normalize_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", str(value or "").strip()).lower()


def fallback_import_root(package_name: str) -> str:
    return normalize_distribution_name(package_name).replace("-", "_")


def infer_package_source_layout(source: Path, package_name: str) -> tuple[Path, str]:
    """Infer analysis root and import root from a source tree without package-name hacks."""
    root = Path(source)
    fallback = fallback_import_root(package_name)
    layouts = [root / "src", root]
    existing_layouts = [layout for layout in layouts if layout.exists() and layout.is_dir()]
    if not existing_layouts:
        return root, fallback

    discovered: list[tuple[Path, set[str]]] = [
        (layout, discover_import_roots(layout))
        for layout in existing_layouts
    ]
    for layout, roots in discovered:
        if fallback in roots:
            return layout, fallback
    for layout, roots in discovered:
        if len(roots) == 1:
            return layout, next(iter(roots))
    for layout, roots in discovered:
        public_roots = sorted(root for root in roots if root not in IGNORED_IMPORT_ROOTS)
        if public_roots:
            return layout, public_roots[0]
    return existing_layouts[0], fallback


def infer_import_root_from_source(source: Path, package_name: str) -> str:
    return infer_package_source_layout(source, package_name)[1]


def discover_import_roots(layout: Path) -> set[str]:
    roots: set[str] = set()
    for child in Path(layout).iterdir() if Path(layout).exists() else []:
        name = child.stem if child.is_file() and child.suffix == ".py" else child.name
        if not _valid_import_root(name):
            continue
        if child.is_file():
            if child.name in {"setup.py", "conftest.py"}:
                continue
            roots.add(name)
        elif child.is_dir() and _contains_python_package_code(child):
            roots.add(name)
    return roots


def summary_payload_import_root(payload: dict[str, Any], package_name: str) -> str:
    explicit = _valid_payload_root(
        payload.get("root")
        or payload.get("import_root")
        or payload.get("importRoot")
        or (payload.get("metadata") or {}).get("root")
        or (payload.get("metadata") or {}).get("import_root")
        or (payload.get("metadata") or {}).get("importRoot")
    )
    if explicit:
        return explicit

    fallback = fallback_import_root(package_name)
    summary = payload.get("summary") or {}
    for section in ("api_aliases", "inner_summary", "outer_summary", "symbol_table", "export_table"):
        roots = _roots_from_mapping(summary.get(section) or {})
        if fallback in roots:
            return fallback
        if len(roots) == 1:
            return next(iter(roots))
    return fallback


def _roots_from_mapping(value: Any) -> set[str]:
    if not isinstance(value, dict):
        return set()
    return {
        root
        for key in value.keys()
        if (root := _root_from_symbol(str(key)))
    }


def _root_from_symbol(value: str) -> str:
    first = str(value or "").split(".", 1)[0]
    return first if _valid_import_root(first) else ""


def _valid_payload_root(value: Any) -> str:
    text = str(value or "").strip().replace("-", "_")
    return text if _valid_import_root(text) else ""


def _valid_import_root(name: str) -> bool:
    return bool(name) and name.isidentifier() and not keyword.iskeyword(name) and name not in IGNORED_IMPORT_ROOTS


def _contains_python_package_code(path: Path) -> bool:
    if (path / "__init__.py").exists():
        return True
    try:
        return any(child.suffix == ".py" for child in path.rglob("*.py"))
    except OSError:
        return False
