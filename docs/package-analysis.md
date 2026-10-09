# Package Analysis

This module statically analyzes Python library source. It builds a complete
library call graph, identifies public APIs, and derives:

- `S_i`: internal functions reachable from each public API.
- `S_o`: external symbols reachable from each public API.

It parses source with `ast` and does not import or execute the target package.

## Python API

High-level source indexing:

```python
from f_vra.analysis.package import index_source

result = index_source(
    "./requests",
    package="requests",
    version="2.30.0",
)

print(result.functions)
print(result.api_count)
```

Inspect the graph and summaries:

```python
from f_vra.analysis.package.callgraph import LibraryAnalyzer
from f_vra.analysis.package.summary import build_library_summary

analyzer = LibraryAnalyzer()
graph = analyzer.build_library_graph("./requests")
summary = build_library_summary(graph, analyzer.index.public_api)

print(summary.inner_summary)
print(summary.outer_summary)
```

## Current CLI Status

`f-vra index package==version` currently preserves the product command
boundary, but remote package resolution/download is not implemented. Use
`index_source()` for production source analysis until a package resolver is
wired into `index_package()`.

## Test

```powershell
pytest tests/unit/test_analysis.py -k package
```

Expected checks include internal call edges, external call edges, `S_i`, and
`S_o`.
