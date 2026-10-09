# Vendored pythonJaRvis engine

This directory contains the execution engine vendored from
`pythonJaRvis/pythonJaRvis.github.io`.

- Upstream commit: `8871b86494a1aec0095686ffa543994a7361af88`
- Upstream repository: https://github.com/pythonJaRvis/pythonJaRvis.github.io
- Included source: `Jarvis/tool/Jarvis` and `Jarvis/tool/pycg`
- Excluded from vendoring: upstream datasets, ground truth, reproduction
  outputs, plots, and website assets

The repository-local Python 3.8 runtime remains outside Git under
`.tools/jarvis-py38`; it is an environment/cache, not engine source.
