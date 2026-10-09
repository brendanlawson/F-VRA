from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PatchFileChange:
    file_path: str
    old_lines: set[int] = field(default_factory=set)
    old_hunk_lines: set[int] = field(default_factory=set)
    new_lines: set[int] = field(default_factory=set)
    added: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    hunk_headers: list[str] = field(default_factory=list)


@dataclass
class PatchAnalysis:
    files: list[PatchFileChange]
    called_names: set[str] = field(default_factory=set)
    changed_names: set[str] = field(default_factory=set)
    changed_globals: set[str] = field(default_factory=set)
    changed_imports: set[str] = field(default_factory=set)
    hunk_symbols: set[str] = field(default_factory=set)


_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_\.]*)\s*\(")
_NAME = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=")
_HUNK = re.compile(r"@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,\d+)?\s+@@\s*(.*)")
_DEF_CLASS = re.compile(r"\b(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
_IMPORT_FROM = re.compile(r"^\s*from\s+[\w\.]+\s+import\s+(.+)")
_IMPORT = re.compile(r"^\s*import\s+(.+)")


def _normalise_path(raw: str) -> str:
    value = raw.strip().split("\t", 1)[0]
    if value.startswith(("a/", "b/")):
        value = value[2:]
    return value.replace("\\", "/")


def parse_patch_text(text: str) -> PatchAnalysis:
    files: list[PatchFileChange] = []
    current: PatchFileChange | None = None
    old_line = new_line = 0

    for line in text.splitlines():
        if line.startswith("+++ "):
            path = _normalise_path(line[4:])
            if path != "/dev/null":
                current = PatchFileChange(file_path=path)
                files.append(current)
            continue
        match = _HUNK.match(line)
        if match:
            old_line, new_line = int(match.group(1)), int(match.group(3))
            old_count = int(match.group(2) or "1")
            if current is not None:
                current.hunk_headers.append(match.group(4).strip())
                if old_count:
                    current.old_hunk_lines.update(range(old_line, old_line + old_count))
                else:
                    # Map insertion-only hunks to adjacent lines in the old tree.
                    current.old_hunk_lines.update({max(1, old_line), max(1, old_line + 1)})
            continue
        if current is None or line.startswith(("diff ", "index ", "--- ")):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current.new_lines.add(new_line)
            current.added.append(line[1:])
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            current.old_lines.add(old_line)
            current.deleted.append(line[1:])
            old_line += 1
        else:
            current.context.append(line[1:] if line.startswith(" ") else line)
            old_line += 1
            new_line += 1

    changed_text = "\n".join(
        line for change in files for line in [*change.added, *change.deleted]
    )
    hunk_symbols = {
        match.group(1)
        for change in files
        for header in change.hunk_headers
        if (match := _DEF_CLASS.search(header))
    }
    called_names = {match.group(1).split(".")[-1] for match in _CALL.finditer(changed_text)}
    changed_names = set(_NAME.findall(changed_text))
    changed_imports: set[str] = set()
    for line in changed_text.splitlines():
        if match := _IMPORT_FROM.match(line):
            changed_imports.update(
                part.strip().split(" as ", 1)[0].split(".")[-1]
                for part in match.group(1).split(",")
                if part.strip()
            )
        elif match := _IMPORT.match(line):
            changed_imports.update(
                part.strip().split(" as ", 1)[0].split(".")[0]
                for part in match.group(1).split(",")
                if part.strip()
            )
    changed_globals = {
        match.group(1)
        for line in changed_text.splitlines()
        if (match := _ASSIGN.match(line))
        and (match.group(1).isupper() or "_" in match.group(1))
    }
    return PatchAnalysis(
        files=files,
        called_names=called_names,
        changed_names=changed_names,
        changed_globals=changed_globals,
        changed_imports=changed_imports,
        hunk_symbols=hunk_symbols,
    )


def load_patch(path: str | Path) -> tuple[PatchAnalysis, str]:
    patch_path = Path(path).resolve()
    return parse_patch_text(patch_path.read_text(encoding="utf-8", errors="ignore")), str(patch_path)
