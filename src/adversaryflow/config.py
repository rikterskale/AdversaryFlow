from __future__ import annotations

import os
from dataclasses import dataclass, field


DEFAULT_ALLOWED_DOMAINS = {
    "attack.mitre.org",
    "github.com",
    "raw.githubusercontent.com",
    "cisa.gov",
    "www.cisa.gov",
    "sigmahq.io",
    "caldera.mitre.org",
    "atomicredteam.io",
    "learn.microsoft.com",
    "docs.splunk.com",
    "elastic.co",
    "www.elastic.co",
}


def _allowed_domains() -> set[str]:
    extra = {
        item.casefold().strip().strip(".")
        for item in os.getenv("ADVERSARYFLOW_ALLOWED_DOMAINS", "").split(",")
        if item.strip()
    }
    return set(DEFAULT_ALLOWED_DOMAINS) | extra


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.casefold() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    llm_base_url: str = field(default_factory=lambda: os.getenv("ADVERSARYFLOW_LLM_BASE_URL", ""))
    llm_api_key: str = field(default_factory=lambda: os.getenv("ADVERSARYFLOW_LLM_API_KEY", ""))
    llm_model: str = field(default_factory=lambda: os.getenv("ADVERSARYFLOW_LLM_MODEL", ""))
    search_provider: str = field(
        default_factory=lambda: os.getenv("ADVERSARYFLOW_SEARCH_PROVIDER", "brave")
    )
    brave_api_key: str = field(default_factory=lambda: os.getenv("ADVERSARYFLOW_BRAVE_API_KEY", ""))
    request_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("ADVERSARYFLOW_REQUEST_TIMEOUT", "45"))
    )
    search_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("ADVERSARYFLOW_SEARCH_TIMEOUT", "15"))
    )
    url_validation_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("ADVERSARYFLOW_URL_TIMEOUT", "10"))
    )
    max_source_bytes: int = field(
        default_factory=lambda: int(os.getenv("ADVERSARYFLOW_MAX_SOURCE_BYTES", "2000000"))
    )
    node_max_attempts: int = field(
        default_factory=lambda: int(os.getenv("ADVERSARYFLOW_NODE_MAX_ATTEMPTS", "3"))
    )
    retry_base_delay_seconds: float = field(
        default_factory=lambda: float(os.getenv("ADVERSARYFLOW_RETRY_BASE_DELAY", "0.25"))
    )
    factuality_threshold: float = field(
        default_factory=lambda: float(os.getenv("ADVERSARYFLOW_FACTUALITY_THRESHOLD", "1.0"))
    )
    fail_on_factuality_error: bool = field(
        default_factory=lambda: _env_bool("ADVERSARYFLOW_FAIL_ON_FACTUALITY", True)
    )
    require_grounded_dossier: bool = field(
        default_factory=lambda: _env_bool("ADVERSARYFLOW_REQUIRE_GROUNDING", True)
    )
    store_dir: str = field(
        default_factory=lambda: os.getenv("ADVERSARYFLOW_STORE_DIR", ".adversaryflow")
    )
    source_cache_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("ADVERSARYFLOW_SOURCE_CACHE_TTL", "86400"))
    )
    allowed_domains: set[str] = field(default_factory=_allowed_domains)
