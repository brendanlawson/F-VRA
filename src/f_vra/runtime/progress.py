from __future__ import annotations

import json
import os
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProgressMonitor:
    """Append-only progress and per-project checkpoint writer.

    The monitor is intentionally usable without optional UI dependencies.  A
    compact line is printed for every phase/package event while the complete
    event remains available in ``progress.jsonl`` for audit and resume.
    """

    def __init__(self, run_root: Path, *, heartbeat_seconds: int = 10):
        self.run_root = run_root.resolve()
        self.run_root.mkdir(parents=True, exist_ok=True)
        self.progress_path = self.run_root / "progress.jsonl"
        self.heartbeat_seconds = heartbeat_seconds
        self._lock = threading.Lock()

    def _resources(self) -> dict[str, Any]:
        result: dict[str, Any] = {"disk_free_bytes": shutil.disk_usage(self.run_root).free}
        try:
            import psutil  # type: ignore

            result.update({"cpu_percent": psutil.cpu_percent(interval=None), "memory_percent": psutil.virtual_memory().percent})
        except Exception:
            result.update({"cpu_percent": None, "memory_percent": None})
        return result

    def emit(self, event: dict[str, Any]) -> None:
        payload = {"timestamp": _now(), **event, "resources": self._resources()}
        line = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        with self._lock:
            with self.progress_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
        project = payload.get("project", "-")
        phase = payload.get("phase", "-")
        detail = payload.get("package") or payload.get("label") or payload.get("line") or ""
        print(f"[{payload['timestamp']}] {project} {phase} {str(detail)[-180:]}", flush=True)

    def checkpoint(self, project_id: str, state: dict[str, Any]) -> Path:
        project_root = self.run_root / project_id
        project_root.mkdir(parents=True, exist_ok=True)
        target = project_root / "project_state.json"
        temp = target.with_suffix(".json.tmp")
        previous: dict[str, Any] = {}
        if target.exists():
            try:
                loaded = json.loads(target.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    previous = loaded
            except (OSError, json.JSONDecodeError):
                previous = {}
        # Preserve immutable run/configuration fields while updating only the
        # current phase.  This is required for safe resume after a package-level
        # checkpoint or an interrupted subprocess.
        payload = {**previous, **state, "updated_at": _now()}
        # A project directory can be resumed after an earlier failed attempt.
        # Do not let that historical error survive into a later successful
        # phase, where it would make the checkpoint look failed even though the
        # current runtime has been captured and is being analyzed.
        if state.get("status") not in {"install_failed", "analysis_failed"}:
            payload.pop("error", None)
            payload.pop("traceback", None)
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True, default=str)
            handle.flush()
            os.fsync(handle.fileno())
        # Windows antivirus/indexing or a concurrent reader can briefly hold
        # the destination open.  Checkpoint persistence must survive that
        # transient sharing violation instead of terminating the whole run.
        replace_error: OSError | None = None
        for attempt in range(8):
            try:
                temp.replace(target)
                replace_error = None
                break
            except PermissionError as exc:
                replace_error = exc
                if attempt == 7:
                    break
                time.sleep(0.15 * (attempt + 1))
        if replace_error is not None:
            raise replace_error
        return target

    def command_progress(self, project_id: str, phase: str, **extra: Any):
        def callback(event: dict[str, Any]) -> None:
            self.emit({"project": project_id, "phase": event.get("phase", phase), **extra, **event})

        return callback
