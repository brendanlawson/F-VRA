from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Lock
from typing import TYPE_CHECKING, Any, Iterator

try:
    from tenacity import retry, stop_after_attempt, wait_exponential
except ImportError:
    def retry(*args: Any, **kwargs: Any):
        def decorator(func: Any) -> Any:
            return func

        return decorator

    def stop_after_attempt(*args: Any, **kwargs: Any) -> None:
        return None

    def wait_exponential(*args: Any, **kwargs: Any) -> None:
        return None

from f_vra.core.config import settings

if TYPE_CHECKING:
    from openai import OpenAI


_client: Any | None = None
_clients: dict[tuple[str, str], Any] = {}


@dataclass(frozen=True)
class ChatProvider:
    name: str
    api_key: str
    base_url: str
    model: str


@dataclass
class ProviderUsage:
    """Per-operation token counters; fields stay null when the provider omits usage."""

    chat_calls: int = 0
    chat_prompt_tokens: int = 0
    chat_completion_tokens: int = 0
    chat_total_tokens: int = 0
    chat_usage_unreported_calls: int = 0
    embedding_calls: int = 0
    embedding_input_tokens: int = 0
    embedding_total_tokens: int = 0
    embedding_usage_unreported_calls: int = 0
    _lock: Any = field(default_factory=Lock, repr=False, compare=False)

    def to_dict(self) -> dict[str, int | None]:
        with self._lock:
            return {
                "chat_calls": self.chat_calls,
                "chat_prompt_tokens": self.chat_prompt_tokens,
                "chat_completion_tokens": self.chat_completion_tokens,
                "chat_total_tokens": self.chat_total_tokens,
                "chat_usage_unreported_calls": self.chat_usage_unreported_calls,
                "embedding_calls": self.embedding_calls,
                "embedding_input_tokens": self.embedding_input_tokens,
                "embedding_total_tokens": self.embedding_total_tokens,
                "embedding_usage_unreported_calls": self.embedding_usage_unreported_calls,
                "cost_usd": None,
            }


_active_usage: ContextVar[ProviderUsage | None] = ContextVar("f_vra_provider_usage", default=None)


@contextmanager
def track_provider_usage() -> Iterator[ProviderUsage]:
    """Collect provider-reported usage in the current execution context only."""
    usage = ProviderUsage()
    token = _active_usage.set(usage)
    try:
        yield usage
    finally:
        _active_usage.reset(token)


def _field(value: Any, *names: str) -> Any:
    for name in names:
        if isinstance(value, dict) and name in value:
            return value[name]
        if value is not None and hasattr(value, name):
            return getattr(value, name)
    return None


def _count(value: Any) -> int | None:
    try:
        return max(0, int(value)) if value is not None else None
    except (TypeError, ValueError):
        return None


def record_chat_usage(response: Any) -> None:
    """Add one successful chat response to the active opt-in usage scope."""
    usage = _active_usage.get()
    if usage is None:
        return
    details = _field(response, "usage")
    prompt = _count(_field(details, "prompt_tokens", "input_tokens"))
    completion = _count(_field(details, "completion_tokens", "output_tokens"))
    total = _count(_field(details, "total_tokens"))
    with usage._lock:
        usage.chat_calls += 1
        if prompt is None and completion is None and total is None:
            usage.chat_usage_unreported_calls += 1
            return
        usage.chat_prompt_tokens += prompt or 0
        usage.chat_completion_tokens += completion or 0
        usage.chat_total_tokens += total if total is not None else (prompt or 0) + (completion or 0)


def record_embedding_usage(response_payload: dict[str, Any]) -> None:
    """Add one successful embedding response to the active opt-in usage scope."""
    usage = _active_usage.get()
    if usage is None:
        return
    details = response_payload.get("usage") or {}
    input_tokens = _count(_field(details, "prompt_tokens", "input_tokens"))
    total = _count(_field(details, "total_tokens"))
    with usage._lock:
        usage.embedding_calls += 1
        if input_tokens is None and total is None:
            usage.embedding_usage_unreported_calls += 1
            return
        usage.embedding_input_tokens += input_tokens if input_tokens is not None else (total or 0)
        usage.embedding_total_tokens += total if total is not None else (input_tokens or 0)


def _configured_providers() -> list[ChatProvider]:
    local_key = settings.local_llm_api_key
    local = (
        ChatProvider(
            name="local",
            api_key=local_key,
            base_url=settings.local_llm_base_url,
            model=settings.local_llm_model,
        )
        if local_key and settings.local_llm_base_url and settings.local_llm_model
        else None
    )
    return [local] if local is not None else []


def chat_available() -> bool:
    return bool(_configured_providers())


def get_client() -> Any:
    global _client
    providers = _configured_providers()
    if not providers:
        raise RuntimeError("No LLM API key is set; configure LOCAL_LLM_API_KEY")
    provider = providers[0]
    if _client is None:
        _client = _client_for(provider)
    return _client


def _client_for(provider: ChatProvider) -> Any:
    key = (provider.name, provider.base_url)
    if key not in _clients:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "openai is required for LLM chat calls; install the server extra"
            ) from exc
        _clients[key] = OpenAI(
            api_key=provider.api_key,
            base_url=provider.base_url,
        )
    return _clients[key]


def provider_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def chat(messages: list[dict], model: str | None = None, temperature: float = 0.0) -> str:
    providers = _configured_providers()
    if not providers:
        raise RuntimeError("No LLM API key is set; configure LOCAL_LLM_API_KEY")

    errors: list[str] = []
    for index, provider in enumerate(providers):
        active_model = model if index == 0 and model else provider.model
        try:
            resp = _client_for(provider).chat.completions.create(
                model=active_model,
                messages=messages,
                temperature=temperature,
            )
            record_chat_usage(resp)
            return resp.choices[0].message.content or ""
        except Exception as exc:
            errors.append(f"{provider.name}: {exc}")
            continue
    raise RuntimeError("LLM chat request failed for all providers: " + " | ".join(errors))


def describe() -> str:
    providers = _configured_providers()
    provider = providers[0] if providers else None
    return (
        f"provider={provider.name if provider else 'none'} "
        f"model={provider.model if provider else settings.llm_model} "
        f"base_url={provider.base_url if provider else settings.llm_base_url}"
    )
