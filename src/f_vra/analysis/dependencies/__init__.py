"""Dependency inventory and package-summary build helpers."""

from f_vra.analysis.dependencies.callgraph_builder import (
    build_dependency_callgraphs,
    source_root_for_record,
)
from f_vra.analysis.dependencies.resolver import resolve_dependency_graph

__all__ = [
    "build_dependency_callgraphs",
    "resolve_dependency_graph",
    "source_root_for_record",
]
