# Vulnerable-Function Knowledge Base

This module defines the storage boundary for CVE-to-vulnerable-function
records.

The core entities are re-exported from `f_vra.core.models`:

- `VulnerabilityRecord`
- `VulnerableEntity`
- `Evidence`

Storage implementations must satisfy `VulnerabilityRepository`:

```python
from f_vra.core.models import VulnerabilityRecord


class VulnerabilityRepository:
    def get(self, cve_id: str) -> VulnerabilityRecord | None:
        ...

    def put(self, record: VulnerabilityRecord) -> None:
        ...
```

## Current Status

The protocol and models exist, but no persistent backend is implemented yet.
Localization reports are currently returned as JSON-compatible objects and are
not automatically stored.

The next storage implementation should preserve:

- CVE and package identity
- affected and fixed version ranges
- vulnerable function or entity
- evidence and source
- role and confidence
- patch and metadata provenance

Add repository contract tests when a SQLite, PostgreSQL, or document-store
adapter is introduced.
