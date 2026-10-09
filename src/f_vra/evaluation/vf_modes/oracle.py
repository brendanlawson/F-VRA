"""Ground-truth-set control runner (no localization or ranking)."""

from pathlib import Path
from typing import Any

from f_vra.evaluation.vf_experiment import run_vf_mode


def run(inputs_dir: Path, results_root: Path, *, run_id: str | None = None, progress: bool = True, workers: int = 1, case_limit: int = 0, case_ids: set[str] | None = None) -> dict[str, Any]:
    return run_vf_mode("ORACLE", inputs_dir, results_root, run_id=run_id, progress=progress, workers=workers, case_limit=case_limit, case_ids=case_ids)
