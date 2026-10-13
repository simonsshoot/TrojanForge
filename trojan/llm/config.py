"""LLM configuration from environment variables."""
from __future__ import annotations

import os


class ConfigError(RuntimeError):
    """Raised when required environment configuration is missing."""


def base_url() -> str:
    """Return the OpenAI-compatible chat-completions base URL (ONEAPI_BASE_URL)."""
    url = os.environ.get("ONEAPI_BASE_URL", "").strip().rstrip("/")
    if not url:
        raise ConfigError(
            "ONEAPI_BASE_URL is not set. Export an OpenAI-compatible endpoint, e.g. "
            "ONEAPI_BASE_URL=https://your-gateway.example.com/v1"
        )
    return url


def forge_model() -> str:
    """Model for strategy synthesis / regeneration (paper default: glm-5.2)."""
    return os.environ.get("TROJAN_FORGE_MODEL", "glm-5.2")


def reach_model() -> str:
    """Model for runtime reach analysis and task synthesis (default: glm-5)."""
    return os.environ.get("TROJAN_REACH_MODEL", "glm-5")


def injector_model() -> str:
    """Model for payload injection (paper default: Kimi K2.6)."""
    return os.environ.get("TROJAN_INJECTOR_MODEL", "Kimi K2.6")


LLM_TIMEOUT_SECONDS = int(os.environ.get("TROJAN_LLM_TIMEOUT", "600"))
LLM_MAX_RETRIES = int(os.environ.get("TROJAN_LLM_MAX_RETRIES", "3"))
