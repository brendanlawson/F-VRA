"""Run inside a frozen target image; standard library only."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import importlib.metadata as metadata
import json
import pathlib
import platform
import re
import sys

PROBE_SCHEMA_VERSION = "environment-probe-v8-normalized-wheel-metadata"


def _symbol_matches(nodes: list[ast.stmt], leaf: str, parents: tuple[str, ...] = ()) -> list[tuple[ast.AST, tuple[str, ...]]]:
    matches: list[tuple[ast.AST, tuple[str, ...]]] = []
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            path = parents + (node.name,)
            if node.name == leaf:
                matches.append((node, path))
            matches.extend(_symbol_matches(node.body, leaf, path))
        elif isinstance(node, ast.ClassDef):
            matches.extend(_symbol_matches(node.body, leaf, parents + (node.name,)))
    return matches


def _bound_anchor(file: pathlib.Path, names: list[str], module: str, requested: str) -> dict | None:
    try:
        text = file.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text, filename=str(file))
    except (SyntaxError, ValueError) as exc:
        return {"status": "UNKNOWN_PARSE_BOUNDARY", "detail": str(exc)}
    nodes = tree.body
    found = None
    for name in names:
        found = next((node for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name), None)
        if found is None:
            break
        nodes = found.body
    resolved_names = tuple(names)
    if found is None or isinstance(found, ast.ClassDef):
        matches = _symbol_matches(tree.body, names[-1]) if names else []
        if len(matches) != 1:
            return None
        found, resolved_names = matches[0]
    segment = ast.get_source_segment(text, found) or ""
    resolved = ".".join(part for part in (module, *resolved_names) if part)
    return {
        "status": "BOUND", "qualified_name": resolved,
        "requested_qualified_name": requested, "module": module,
        "file": str(file), "start_line": found.lineno,
        "end_line": found.end_lineno or found.lineno,
        "function_hash": hashlib.sha256(segment.encode("utf-8")).hexdigest(),
    }


def _anchor(package: dict, qualified_name: str) -> dict:
    parts = qualified_name.split(".")
    if parts and parts[0] == "src":
        parts = parts[1:]
    available_roots = {root for root, path in package["import_root_paths"].items() if path}
    root_index = next((index for index, part in enumerate(parts) if part in available_roots), None)
    if root_index is not None:
        parts = parts[root_index:]
    if not parts:
        return {"status": "UNKNOWN_VF_MISMATCH"}
    root = parts[0]
    source_text = package["import_root_paths"].get(root)
    if not source_text:
        return {"status": "UNKNOWN_SOURCE"}
    source = pathlib.Path(source_text)
    candidates = []
    if source.is_file():
        if source.suffix != ".py":
            return {"status": "UNKNOWN_SOURCE"}
        candidates.append((source, parts[1:], root))
    else:
        for split in range(len(parts) - 1, 0, -1):
            module_parts = parts[1:split]
            base = source.joinpath(*module_parts) if module_parts else source
            module = ".".join(parts[:split])
            candidates.extend([
                (base.with_suffix(".py"), parts[split:], module),
                (base / "__init__.py", parts[split:], module),
            ])
    parse_error = None
    fallback_matches = []
    for file, names, module in candidates:
        if not file.is_file() or not names:
            continue
        bound = _bound_anchor(file, names, module, qualified_name)
        if bound and bound["status"] == "BOUND":
            fallback_matches.append(bound)
        elif bound and bound["status"] == "UNKNOWN_PARSE_BOUNDARY":
            parse_error = bound
    unique = {(item["file"], item["start_line"], item["function_hash"]): item for item in fallback_matches}
    if len(unique) == 1:
        return next(iter(unique.values()))
    if parse_error is not None:
        return parse_error
    return {"status": "UNKNOWN_VF_MISMATCH"}


def _hash_files(dist: metadata.Distribution) -> tuple[str, str, list[str], bool, bool]:
    source_digest = hashlib.sha256()
    artifact_digest = hashlib.sha256()
    tags: list[str] = []
    has_python = False
    has_native = False
    for file in sorted(dist.files or (), key=lambda item: item.as_posix()):
        name = file.as_posix()
        if name.endswith(".dist-info/WHEEL"):
            path = pathlib.Path(dist.locate_file(file))
            if path.is_file():
                data = path.read_bytes()
                lines = data.decode("utf-8", errors="replace").splitlines()
                # A locally built wheel records the active setuptools version in
                # Generator. That field does not change source, ABI, platform or
                # analysis semantics and makes repeated sdist builds unstable.
                normalized = "\n".join(line for line in lines if not line.startswith("Generator:")) + "\n"
                artifact_digest.update(name.encode("utf-8") + b"\0" + normalized.encode("utf-8"))
                tags.extend(line.split(":", 1)[1].strip() for line in lines if line.startswith("Tag:"))
        if not name.endswith((".py", ".so", ".pyd", ".dll", ".dylib")):
            continue
        if name.endswith(".py"):
            has_python = True
        else:
            has_native = True
        path = pathlib.Path(dist.locate_file(file))
        if not path.is_file():
            continue
        if name.endswith(".py"):
            source_digest.update(name.encode("utf-8") + b"\0")
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    source_digest.update(chunk)
    if not has_python:
        # Compiled extensions can contain timestamps/build IDs even when the
        # source and toolchain are unchanged. They are native boundaries for
        # this AST study, so use stable installed metadata as their source
        # identity and retain ABI/platform separately in PackageID.
        source_digest.update((dist.read_text("METADATA") or "").encode("utf-8"))
    return source_digest.hexdigest(), artifact_digest.hexdigest(), sorted(tags), has_python, has_native


def _roots(dist: metadata.Distribution) -> list[str]:
    top_level = dist.read_text("top_level.txt") or ""
    roots = {line.strip() for line in top_level.splitlines() if line.strip() and line.strip().isidentifier()}
    if not roots:
        for file in dist.files or ():
            parts = file.parts
            if len(parts) >= 2 and parts[1] == "__init__.py" and parts[0].isidentifier():
                roots.add(parts[0])
            elif len(parts) == 1 and parts[0].endswith(".py"):
                stem = pathlib.Path(parts[0]).stem
                if stem.isidentifier():
                    roots.add(stem)
    if not roots:
        # Editable installs commonly expose only a .pth file in RECORD. Resolve
        # the canonical distribution spelling through the active interpreter.
        name = (dist.metadata.get("Name") or "").replace("-", "_")
        candidates = {name, name.split(".", 1)[0]}
        for candidate in candidates:
            if not candidate.isidentifier():
                continue
            try:
                spec = importlib.util.find_spec(candidate)
            except (ImportError, AttributeError, ValueError):
                spec = None
            if spec is not None and (spec.origin or spec.submodule_search_locations):
                roots.add(candidate)
    return sorted(roots)


def _hash_roots(root_paths: dict[str, str], fallback: str) -> tuple[str, bool, bool]:
    digest = hashlib.sha256()
    has_python = False
    has_native = False
    for root, raw_path in sorted(root_paths.items()):
        path = pathlib.Path(raw_path)
        files = [path] if path.is_file() else sorted(item for item in path.rglob("*") if item.is_file())
        for file in files:
            if file.suffix not in {".py", ".so", ".pyd", ".dll", ".dylib"}:
                continue
            has_python |= file.suffix == ".py"
            has_native |= file.suffix != ".py"
            if file.suffix != ".py":
                continue
            relative = file.name if path.is_file() else file.relative_to(path).as_posix()
            digest.update(f"{root}/{relative}".encode("utf-8") + b"\0")
            with file.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
    value = digest.hexdigest()
    return (value if has_python else fallback), has_python, has_native


def _root_paths(dist: metadata.Distribution, roots: list[str]) -> dict[str, str]:
    paths = {}
    for root in roots:
        root_directory = pathlib.Path(dist.locate_file(root))
        candidates = [root_directory / "__init__.py", pathlib.Path(dist.locate_file(root + ".py"))]
        try:
            spec = importlib.util.find_spec(root)
        except (ImportError, AttributeError, ValueError):
            spec = None
        if spec and spec.origin and spec.origin not in {"built-in", "frozen"} and pathlib.Path(spec.origin).suffix == ".py":
            candidates.insert(0, pathlib.Path(spec.origin))
        for candidate in candidates:
            if candidate.is_file():
                paths[root] = str(candidate.parent if candidate.name == "__init__.py" else candidate)
                break
        # PEP 420 namespace packages intentionally have no __init__.py.
        # The distribution metadata still identifies the top-level root,
        # so retain the directory and let the common AST/JARVIS adapter
        # inventory the modules contributed beneath it.
        if root not in paths and root_directory.is_dir():
            paths[root] = str(root_directory)
    return paths


def main() -> None:
    packages = []
    for dist in metadata.distributions():
        name = dist.metadata.get("Name") or ""
        if not name:
            continue
        source_hash, wheel_hash, wheel_tags, has_python, has_native = _hash_files(dist)
        roots = _roots(dist)
        root_paths = _root_paths(dist, roots)
        if not has_python and not has_native and root_paths:
            source_hash, has_python, has_native = _hash_roots(root_paths, source_hash)
        packages.append({
            "name": name, "version": dist.version, "source_hash": source_hash,
            "wheel_hash": wheel_hash, "wheel_tags": wheel_tags,
            "import_roots": roots, "import_root_paths": root_paths,
            "has_python": has_python, "has_native": has_native,
            "requires_dist": sorted(dist.requires or ()),
        })
    packages.sort(key=lambda row: (row["name"].lower(), row["version"]))
    anchors = {}
    if len(sys.argv) > 1:
        for request in json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")):
            requested_distribution = re.sub(r"[-_.]+", "-", request["distribution"].lower())
            package = next((
                item for item in packages
                if re.sub(r"[-_.]+", "-", item["name"].lower()) == requested_distribution
            ), None)
            key = request["distribution"] + "|" + request["qualified_name"]
            anchors[key] = _anchor(package, request["qualified_name"]) if package else {"status": "UNKNOWN_PACKAGE_MAPPING"}
    print(json.dumps({
        "probe_schema_version": PROBE_SCHEMA_VERSION,
        "python_version": platform.python_version(),
        "python_abi": f"{sys.implementation.name}-{sys.version_info.major}{sys.version_info.minor}",
        "platform": f"{sys.platform}-{platform.machine().lower()}",
        "packages": packages,
        "anchors": anchors,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
