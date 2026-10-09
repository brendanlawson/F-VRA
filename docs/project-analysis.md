# Project Analysis

This module analyzes the application side of reachability.

It discovers entry points, walks only project code reachable from those entry
points, and produces a Usage Index containing external APIs called by reachable
code.

Recognized entry-point signals include:

- calls under `if __name__ == "__main__"`
- CLI decorators such as `@app.command`
- web route decorators such as `@app.get` and `@router.post`
- pytest-style test functions in the standalone scanner

The analyzer uses static `ast` parsing and never executes project code.

## Python API

Discover entry points:

```python
from f_vra.analysis.project import scan_project

entrypoints = scan_project("./myapp")
for entrypoint in entrypoints:
    print(entrypoint.qualified_name, entrypoint.entry_type)
```

Build the reachable project graph and Usage Index:

```python
from f_vra.analysis.project import build_project_graph

graph, usage_index = build_project_graph("./myapp")

for edge in graph.edges:
    print(edge.caller.qualified_name, "->", edge.callee.qualified_name)

for external in usage_index:
    print(external.identity_string)
```

Only external calls reached from detected entry points should appear in the
Usage Index. Calls in dead or unreachable helpers should not appear.

## Test

```powershell
pytest tests/unit/test_analysis.py -k project
```

The fixture verifies entry-point discovery, reachable internal edges, external
API usage, and exclusion of an unused external call.
