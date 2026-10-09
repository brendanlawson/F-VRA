# Project entrypoint policy

## Included entrypoints

Project graphs start from statically discovered production-facing functions:

- functions invoked from `if __name__ == "__main__"`;
- CLI commands and callbacks;
- web and websocket routes;
- maintenance commands under `scripts/` when they satisfy one of the rules above.

## Excluded entrypoints

Pytest functions are excluded. Files below directories named `tests`, `test`,
`docs`, `examples`, `example`, `tutorials`, `benchmarks`, or `benchmark` are
excluded from entrypoint discovery and AST project-boundary inventory.

The exclusion avoids treating test-only and documentation-only dependency use
as production application reachability. Maintenance scripts remain included
because they are executable project behavior and can process production data.

## Empty entrypoint set

If no eligible entrypoint is discovered, the project graph must not fall back
to every Python file. The environment is recorded with an empty entrypoint set,
and affected queries become `UNKNOWN_UNRESOLVED_FRONTIER` rather than
`UNREACHABLE`.

## Changes

Changing this policy requires a new protocol and dataset version. Existing run
artifacts must not be mixed with runs from the revised policy.
