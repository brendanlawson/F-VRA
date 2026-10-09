from __future__ import annotations

import time
from pathlib import Path

from f_vra.core.models import IndexResult
from f_vra.analysis.package.callgraph import LibraryAnalyzer
from f_vra.analysis.package.summary import build_library_summary


def index_source(source_root: str | Path, *, package: str = "", version: str = "") -> IndexResult:
    started = time.perf_counter()
    analyzer = LibraryAnalyzer()
    graph = analyzer.build_library_graph(Path(source_root))
    public_apis = analyzer.index.public_api if analyzer.index is not None else []
    build_library_summary(graph, public_apis)
    return IndexResult(
        package=package or Path(source_root).name,
        version=version,
        functions=len(graph.nodes),
        api_count=len(public_apis),
        elapsed_s=time.perf_counter() - started,
    )


def index_package(package: str, version: str) -> IndexResult:
    """Production placeholder for package indexing.

    The current product direction deliberately excludes baseline SCA and remote
    package resolution. For now this command expects source indexing to be called
    through `index_source`; package download/resolution can be added behind this
    boundary later.
    """
    return IndexResult(package=package, version=version)
