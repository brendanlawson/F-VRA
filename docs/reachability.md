# Reachability
This module composes:

- the project Usage Index
- package `S_i` and `S_o` summaries
- known vulnerable-function names

It performs path-aware breadth-first search and returns concrete paths that
reach a vulnerable function.

## Python API

```python
from f_vra.core.models import ExternalNode, LibrarySummary
from f_vra.reachability.engine import ReachabilityQueryEngine

usage_index = [
    ExternalNode(
        file_path="<external:sample>",
        function_name="sample.public_api",
        qualified_name="sample.public_api",
        target_module="sample",
        target_name="public_api",
    )
]

summaries = {
    "sample": LibrarySummary(
        inner_summary={
            "sample.public_api": {"sample.Client.fetch"},
        },
        outer_summary={
            "sample.public_api": {"requests.get"},
        },
    )
}

report = ReachabilityQueryEngine(
    usage_index,
    summaries,
    vulnerabilities={"requests.get"},
).check_reachability()

print(report.is_vulnerable)
for path in report.paths:
    print(" -> ".join(path.tpl_chain))
```

The engine checks direct vulnerable calls before summary expansion, then
follows `S_o` across package boundaries. Vulnerabilities can match either
internal `S_i` functions or external `S_o` targets.

## Current CLI Status

`f-vra scan` exists as the product boundary, but
`f_vra.reachability.service.query()` currently returns `UNKNOWN`. Use
`ReachabilityQueryEngine` directly until the KB, project analyzer, and stored
package summaries are wired into the service.

## Test

```powershell
pytest tests/unit/test_reachability.py
```

Tests cover direct vulnerable usage and summary-based cross-library expansion.
