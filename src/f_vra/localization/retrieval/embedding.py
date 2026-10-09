from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
import zlib
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextvars import copy_context
from pathlib import Path
from typing import Protocol

import requests
from tqdm import tqdm

from f_vra.core.config import settings
from f_vra.localization.providers.llm_client import provider_headers, record_embedding_usage
from f_vra.localization.models import FunctionInfo


class EmbeddingBackend(Protocol):
    """Embedding provider; must tolerate concurrent calls when workers > 1."""

    model_name: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class OpenAICompatibleEmbeddingBackend:
    def __init__(
        self,
        *,
        model_name: str,
        api_key: str,
        base_url: str,
        provider_name: str,
    ) -> None:
        self.model_name = model_name
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.provider_name = provider_name
        if not api_key:
            raise RuntimeError(f"{provider_name} embedding API key is not set")

    def embed(self, texts: list[str]) -> list[list[float]]:
        response = None
        for attempt in range(3):
            try:
                payload = {
                    "model": self.model_name,
                    "input": texts,
                    "encoding_format": "float",
                }
                response = requests.post(
                    f"{self.base_url}/embeddings",
                    headers=provider_headers(self.api_key),
                    json=payload,
                    timeout=90,
                )
            except requests.RequestException as exc:
                if attempt == 2:
                    raise RuntimeError(f"{self.provider_name} embeddings request failed: {exc}") from exc
                time.sleep(2**attempt)
                continue
            if response.status_code == 200:
                break
            if response.status_code not in {429, 529} or attempt == 2:
                raise RuntimeError(
                    f"{self.provider_name} embeddings returned HTTP {response.status_code}: "
                    f"{response.text[:300]}"
                )
            time.sleep(2**attempt)

        if response is None:
            raise RuntimeError(f"{self.provider_name} embeddings request did not produce a response")
        payload = response.json()
        record_embedding_usage(payload)
        data = sorted(payload.get("data", []), key=lambda item: item.get("index", 0))
        if len(data) != len(texts):
            raise RuntimeError(
                f"{self.provider_name} embeddings returned {len(data)} vectors for {len(texts)} inputs"
            )
        return [item["embedding"] for item in data]


class LocalEmbeddingBackend(OpenAICompatibleEmbeddingBackend):
    def __init__(self, model_name: str | None = None) -> None:
        super().__init__(
            model_name=model_name or settings.local_embedding_model,
            api_key=settings.local_embedding_api_key or settings.local_llm_api_key,
            base_url=settings.local_embedding_base_url,
            provider_name="local",
        )


class AutoEmbeddingBackend:
    def __init__(self) -> None:
        backends: list[EmbeddingBackend] = []
        local_ready = bool(
            (settings.local_embedding_api_key or settings.local_llm_api_key)
            and settings.local_embedding_base_url
            and settings.local_embedding_model
        )
        if local_ready:
            backends.append(LocalEmbeddingBackend())
        if not backends:
            raise RuntimeError(
                "No embedding API key is set; configure LOCAL_EMBEDDING_API_KEY, "
                "or LOCAL_LLM_API_KEY"
            )
        self.backends = backends
        self.model_name = backends[0].model_name

    def embed(self, texts: list[str]) -> list[list[float]]:
        errors: list[str] = []
        for backend in self.backends:
            try:
                vectors = backend.embed(texts)
                self.model_name = backend.model_name
                return vectors
            except RuntimeError as exc:
                errors.append(f"{getattr(backend, 'model_name', 'unknown')}: {exc}")
        raise RuntimeError("All embedding providers failed: " + " | ".join(errors))


def function_embedding_text(function: FunctionInfo, max_chars: int = 4000) -> str:
    structural = " ".join(
        [
            function.qualname,
            function.file_path,
            " ".join(sorted(function.calls)),
            " ".join(function.decorators),
        ]
    )
    text = f"{structural}\n{function.docstring}\n{function.source}".strip()
    return text if len(text) <= max_chars else text[:max_chars]


def _cosine(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    denominator = left_norm * right_norm
    return dot / denominator if denominator else 0.0


def _embedding_key(model_name: str, text: str) -> str:
    digest = hashlib.sha256()
    digest.update(b"f_vra.embedding-cache.v1\0")
    digest.update(model_name.encode("utf-8"))
    digest.update(b"\0")
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def _read_cached_vectors(connection: sqlite3.Connection, keys: list[str]) -> dict[str, list[float]]:
    cached: dict[str, list[float]] = {}
    for start in range(0, len(keys), 500):
        chunk = keys[start : start + 500]
        placeholders = ",".join("?" for _ in chunk)
        for key, compressed in connection.execute(
            f"SELECT cache_key, vector FROM embedding_vectors WHERE cache_key IN ({placeholders})", chunk,
        ):
            cached[str(key)] = json.loads(zlib.decompress(compressed))
    return cached


def _store_cached_vectors(
    connection: sqlite3.Connection, rows: list[tuple[str, list[float]]],
) -> None:
    connection.executemany(
        "INSERT OR IGNORE INTO embedding_vectors(cache_key, vector) VALUES (?, ?)",
        [
            (key, zlib.compress(json.dumps(vector, separators=(",", ":")).encode("utf-8"), level=1))
            for key, vector in rows
        ],
    )
    connection.commit()


def embedding_scores(
    description: str,
    functions: list[FunctionInfo],
    *,
    backend: EmbeddingBackend | None = None,
    cache_path: Path | None = None,
) -> tuple[dict[str, float], str]:
    if not functions:
        return {}, "not_run"

    active_backend = backend or AutoEmbeddingBackend()
    texts = [description, *(function_embedding_text(function) for function in functions)]
    cache_model = "\0".join((
        active_backend.model_name,
        str(getattr(active_backend, "provider_name", "")),
        str(getattr(active_backend, "base_url", "")),
    ))
    keys = [_embedding_key(cache_model, text) for text in texts]
    connection: sqlite3.Connection | None = None
    try:
        cached: dict[str, list[float]] = {}
        if cache_path is not None:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(str(cache_path), timeout=60)
            connection.execute("PRAGMA busy_timeout=60000")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS embedding_vectors ("
                "cache_key TEXT PRIMARY KEY, vector BLOB NOT NULL)"
            )
            cached = _read_cached_vectors(connection, keys)

        vectors_by_key = dict(cached)
        missing_positions = [index for index, key in enumerate(keys) if key not in cached]
        batch_size = max(1, int(settings.embedding_batch_size))
        batches = [
            missing_positions[start : start + batch_size]
            for start in range(0, len(missing_positions), batch_size)
        ]
        max_workers = max(1, int(settings.embedding_max_workers))

        def persist_batch(positions: list[int], batch_vectors: list[list[float]]) -> None:
            if len(batch_vectors) != len(positions):
                raise RuntimeError(
                    f"embedding backend returned {len(batch_vectors)} vectors for {len(positions)} inputs"
                )
            new_rows = [(keys[index], vector) for index, vector in zip(positions, batch_vectors)]
            vectors_by_key.update(new_rows)
            if connection is not None:
                _store_cached_vectors(connection, new_rows)

        if max_workers == 1 or len(batches) <= 1:
            for positions in tqdm(batches, desc="Embedding batches"):
                persist_batch(positions, active_backend.embed([texts[index] for index in positions]))
        else:
            bar = tqdm(total=len(batches), desc=f"Embedding batches ({max_workers} workers)")
            batch_iterator = iter(batches)
            pending = {}
            failure: Exception | None = None
            with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="f_vra-embedding") as executor:
                def submit_next() -> bool:
                    try:
                        positions = next(batch_iterator)
                    except StopIteration:
                        return False
                    payload = [texts[index] for index in positions]
                    context = copy_context()
                    future = executor.submit(context.run, active_backend.embed, payload)
                    pending[future] = positions
                    return True

                for _ in range(max_workers):
                    if not submit_next():
                        break
                while pending:
                    completed, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
                    for future in completed:
                        positions = pending.pop(future)
                        try:
                            persist_batch(positions, future.result())
                        except Exception as exc:
                            if failure is None:
                                failure = exc
                        finally:
                            bar.update(1)
                    if failure is None:
                        while len(pending) < max_workers and submit_next():
                            pass
            bar.close()
            if failure is not None:
                raise failure
        vectors = [vectors_by_key[key] for key in keys]
    finally:
        if connection is not None:
            connection.close()

    query_vector = vectors[0]
    scores = {
        function.identity: _cosine(query_vector, vectors[index + 1])
        for index, function in enumerate(functions)
    }
    return scores, active_backend.model_name
