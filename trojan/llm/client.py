"""Synchronous client for an OpenAI-compatible chat-completions endpoint.

All configuration comes from the environment (see ``trojan.llm.config``);
API keys rotate round-robin from the ``ONEAPI_KEYS`` environment variable
(comma-separated; no keys are stored in the repository). Failures are
retried with exponential backoff; exhausted retries raise :class:`LLMError`.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Optional

import requests

from . import config

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS = {401, 404, 408, 409, 425, 429, 500, 502, 503, 504}

# Thread-safe round-robin rotation over ONEAPI_KEYS. There is no built-in
# default; callers fail fast when no key is configured.
_key_lock = threading.Lock()
_key_index = 0


def _next_key() -> str:
    """Return the next API key (round-robin, thread-safe)."""
    global _key_index
    env = os.environ.get("ONEAPI_KEYS", "").strip()
    keys = [k.strip() for k in env.split(",") if k.strip()]
    if not keys:
        raise RuntimeError(
            "ONEAPI_KEYS is not set. Export a comma-separated list of API keys."
        )
    with _key_lock:
        key = keys[_key_index % len(keys)]
        _key_index += 1
    return key


class LLMError(RuntimeError):
    pass


def complete(prompt: str,
             model: Optional[str] = None,
             max_retries: Optional[int] = None,
             timeout: Optional[int] = None) -> str:
    """Call the chat-completions endpoint once and return the text content."""
    retries = max_retries if max_retries is not None else config.LLM_MAX_RETRIES
    timeout = timeout if timeout is not None else config.LLM_TIMEOUT_SECONDS
    model_name = model or config.reach_model()
    url = config.base_url() + "/chat/completions"

    last_err: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            logger.info("LLM call attempt=%d model=%s prompt_len=%d",
                        attempt, model_name, len(prompt))
            resp = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {_next_key()}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model_name,
                    "temperature": 0.9,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=timeout,
            )
            if resp.status_code != 200:
                raise LLMError(f"HTTP {resp.status_code}: {resp.text[:300]}")
            result = resp.json()
            if "error" in result:
                raise LLMError(f"API error: {result['error']}")
            content = result["choices"][0]["message"]["content"]
            if not content or (isinstance(content, str) and not content.strip()):
                raise LLMError("empty content from LLM")
            logger.info("LLM call ok len=%d", len(content))
            return content
        except Exception as e:
            last_err = e
            logger.warning("LLM call failed attempt=%d err=%s", attempt, e)
            if attempt < retries:
                time.sleep(min(5.0 * (2 ** attempt), 120.0))

    raise LLMError(f"LLM call failed after {retries + 1} attempts: {last_err}")


def complete_json(prompt: str, model: Optional[str] = None) -> dict:
    """Call the LLM and parse the response as a JSON object."""
    from .json_utils import extract_json
    text = complete(prompt, model=model)
    obj = extract_json(text)
    if not isinstance(obj, dict):
        raise LLMError(f"LLM output is not a JSON object: {text[:200]}")
    return obj
