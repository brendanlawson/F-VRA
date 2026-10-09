# Dataset Card

## Layout

F-VRA benchmark data follows this structure:

- `data/raw/`: projects, SCA outputs, patches, and advisories.
- `data/interim/`: normalized intermediate data.
- `data/annotations/`: vulnerable-function and path labels.
- `data/processed/`: final benchmark records.
- `artifacts/`: package summaries, query caches, and witnesses.
- `results/`: tables, figures, metrics, and logs.

## Mock Transitive VF Case

`CVE-MOCK-0001` is a minimal offline case:

```text
mock_transitive_project.run
  -> mocklib_a.safe_entry
  -> mocklib_b.bridge
  -> mockvuln.dangerous_sink
```

The mock case validates that F-VRA can compose multiple package summaries and
detect a vulnerable function that is only reachable through a transitive
dependency.
