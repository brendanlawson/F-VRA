# F-VRA Documentation

F-VRA maps disclosed vulnerabilities to vulnerable Python functions and
checks whether application usage can reach them.

## Module Documentation

| Module | Responsibility |
| --- | --- |
| [Localization](localization.md) | Resolve CVE metadata and patches, extract functions, retrieve candidates, and rank vulnerable functions |
| [Package analysis](package-analysis.md) | Build library call graphs, public API indexes, and `S_i` / `S_o` summaries |
| [Project analysis](project-analysis.md) | Discover entry points, build the reachable project graph, and produce the Usage Index |
| [Reachability](reachability.md) | Compose project usage and package summaries into vulnerability paths |
| [Knowledge base](knowledge-base.md) | Define vulnerable-function records and persistence contracts |
| [Dataset card](dataset-card.md) | Dataset layout, annotations, artifacts, and the mock transitive VF case |

## Development

```powershell
pip install -e ".[dev]"
pytest
```

Dataset conventions are documented in
[`data/README.md`](../data/README.md), [`artifacts/README.md`](../artifacts/README.md),
and the [dataset card](dataset-card.md).
