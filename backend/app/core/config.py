"""Application configuration.

All tunables can be overridden through environment variables or a `.env` file
at the repository root. No secret is ever hard-coded here.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    """Runtime settings for the PhishGuard AI backend."""

    model_config = SettingsConfigDict(
        env_file=(PROJECT_ROOT / ".env", BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "PhishGuard AI"
    app_version: str = "1.0.0"
    api_prefix: str = "/api/v1"
    environment: str = "development"
    debug: bool = False

    database_url: str = f"sqlite:///{BACKEND_DIR / 'phishguard.db'}"

    # Comma-separated origins. Kept explicit (no wildcard) by default.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    artifacts_dir: Path = BACKEND_DIR / "artifacts"

    max_email_chars: int = 50_000
    max_url_chars: int = 2_048
    max_urls_per_email: int = 5
    max_body_chars_for_llm: int = 6_000

    # ---- Risk engine -------------------------------------------------
    weight_email_model: float = 0.30
    weight_url_model: float = 0.30
    weight_email_rules: float = 0.15
    weight_url_rules: float = 0.10
    weight_graph: float = 0.05
    weight_llm: float = 0.10

    # Popularity is a weak prior, not a whitelist. When the host *is* the bare
    # registrable domain of a top-ranked Umbrella domain (not a subdomain of a
    # popular hosting platform), the URL model probability is shrunk by this
    # factor. Deterministic URL rules still apply in full. Set to 1.0 to disable.
    url_popularity_calibration: float = 0.3

    threshold_suspicious: int = 30
    threshold_high: int = 60
    threshold_critical: int = 80
    corroboration_high_score: int = 60
    corroboration_bonus: int = 4
    corroboration_max_bonus: int = 8

    # ---- Local LLM (fine-tuned DistilBERT classifier) ------------------
    # Local inference never sends email content off-machine. It is enabled by
    # default because it is private; the external API remains opt-in.
    local_llm_enabled: bool = True
    local_llm_max_length: int = 384
    local_llm_device: str = "auto"  # auto | cpu | cuda

    # ---- Optional external LLM ----------------------------------------
    llm_enabled: bool = False
    llm_api_key: str | None = None
    llm_model: str = "gpt-4o-mini"
    llm_base_url: str = "https://api.openai.com/v1"
    llm_timeout_seconds: float = 12.0
    llm_max_tokens: int = 600

    @field_validator("artifacts_dir", mode="before")
    @classmethod
    def _resolve_artifacts(cls, value: str | Path) -> Path:
        path = Path(value)
        return path if path.is_absolute() else (BACKEND_DIR / path).resolve()

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def llm_configured(self) -> bool:
        """An external API call is possible only when enabled *and* keyed."""
        return bool(self.llm_enabled and self.llm_api_key)

    @property
    def local_llm_dir(self) -> Path:
        """Directory holding the fine-tuned local transformer and tokenizer."""
        return self.artifacts_dir / "local_llm"

    @property
    def any_llm_enabled(self) -> bool:
        """True when either the private local model or the external API may run."""
        return bool(self.local_llm_enabled or self.llm_configured)

    def component_weights(self) -> dict[str, float]:
        return {
            "email_model": self.weight_email_model,
            "url_model": self.weight_url_model,
            "email_rules": self.weight_email_rules,
            "url_rules": self.weight_url_rules,
            "graph": self.weight_graph,
            "llm": self.weight_llm,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
