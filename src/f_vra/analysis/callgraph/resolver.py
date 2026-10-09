"""Resolver primitives shared by package and project call graph builders."""

from f_vra.analysis.callgraph.engine import ClassInfo, LibraryIndex, ModuleScope, _dotted_name

__all__ = ["ClassInfo", "LibraryIndex", "ModuleScope", "_dotted_name"]
