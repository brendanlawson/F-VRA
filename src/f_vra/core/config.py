from pathlib import Path
import os
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    anthropic_api_key: str = ""
    neo4j_uri:         str = "bolt://localhost:7687"
    neo4j_user:        str = "neo4j"
    neo4j_password:    str = ""

    index_dir:     Path = Path.home() / ".f_vra" / "index"
    cve_cache_dir: Path = Path.home() / ".f_vra" / "cve"
    repo_cache_dir: Path = Path.home() / ".f_vra" / "repos"
    client_cache_dir: Path = Path.home() / ".f_vra" / "client"
    server_store_dir: Path = Path.home() / ".f_vra" / "server"
    f_vra_rq3_snapshot_root: Path = Field(
        default_factory=lambda: Path.home() / "rq3-snapshots",
        validation_alias="F_VRA_RQ3_SNAPSHOT_ROOT",
    )

    bm25_top_k: int = 100
    llm_top_k: int = 20
    llm_batch_size: int = 10
    embedding_batch_size: int = 16
    embedding_max_workers: int = Field(default=1, ge=1, le=8)
    github_token: str = ""
    nvd_api_key: str = ""
    local_llm_api_key: str = ""
    local_llm_base_url: str = ""
    local_llm_model: str = ""
    llm_provider: str = "auto"
    llm_fallback_provider: str = ""
    local_embedding_api_key: str = ""
    local_embedding_base_url: str = ""
    local_embedding_model: str = ""
    callgraph_llm_model: str = ""
    callgraph_llm_threshold: float = 0.75
    callgraph_llm_limit: int = 0

    @property
    def llm_api_key(self) -> str:
        return self.local_llm_api_key

    @property
    def llm_base_url(self) -> str:
        return self.local_llm_base_url

    @property
    def llm_model(self) -> str:
        override = os.getenv("LLM_MODEL_OVERRIDE")
        if override:
            return override
        return self.local_llm_model

    @property
    def embedding_api_key(self) -> str:
        return self.local_embedding_api_key or self.local_llm_api_key

    @property
    def embedding_base_url(self) -> str:
        if self.embedding_api_key and self.local_embedding_base_url:
            return self.local_embedding_base_url
        return ""

    @property
    def embedding_model(self) -> str:
        override = os.getenv("EMBEDDING_MODEL_OVERRIDE")
        if override:
            return override
        if (self.local_embedding_api_key or self.local_llm_api_key) and self.local_embedding_model:
            return self.local_embedding_model
        return ""

    @property
    def callgraph_model(self) -> str:
        override = os.getenv("CALLGRAPH_LLM_MODEL_OVERRIDE")
        if override:
            return override
        return self.callgraph_llm_model or self.llm_model

settings = Settings()
