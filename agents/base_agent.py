"""
agents/base_agent.py — Abstract Base Agent

Provides shared infrastructure for all three swarm agents:
  - Gemini client (Explorer, Evaluator)
  - Groq client (Mutator)
  - Exponential back-off wrapper for rate limits
  - Structured JSON extraction from LLM responses
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from abc import ABC
from typing import Any, Optional

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    retry_if_not_exception_type,
)

from config import config

logger = logging.getLogger("BaseAgent")


class GeminiQuotaExhaustedError(RuntimeError):
    """All configured Gemini API keys are currently rate-limited."""


def _is_rate_limit_error(exc: Exception) -> bool:
    """Best-effort detection of Gemini 429 and quota-exhaustion errors."""
    msg = str(exc).lower()
    return any(s in msg for s in ("429", "resource_exhausted", "rate limit", "quota"))


def _parse_retry_delay(exc: Exception) -> Optional[float]:
    """Extract a server-suggested retry delay in seconds, if present."""
    match = re.search(
        r"retrydelay['\"]?\s*[:=]\s*['\"]?(\d+(?:\.\d+)?)s",
        str(exc).lower(),
    )
    return float(match.group(1)) if match else None


class GeminiKeyPool:
    """Rotate across Gemini keys and temporarily cool down rate-limited keys."""

    DEFAULT_COOLDOWN_SECONDS = 65.0

    def __init__(self, api_keys: list[str]):
        if not api_keys:
            raise ValueError("GeminiKeyPool needs at least one API key")
        self._keys = api_keys
        self._clients: dict[int, Any] = {}
        self._cooldown_until: dict[int, float] = {}
        self._cursor = 0

    def _client_for(self, idx: int):
        if idx not in self._clients:
            from google import genai as google_genai
            self._clients[idx] = google_genai.Client(api_key=self._keys[idx])
        return self._clients[idx]

    def current(self):
        """Return the next available (index, client), or None if all cool down."""
        for offset in range(len(self._keys)):
            idx = (self._cursor + offset) % len(self._keys)
            if time.time() >= self._cooldown_until.get(idx, 0.0):
                self._cursor = idx
                return idx, self._client_for(idx)
        return None

    def seconds_until_next_available(self) -> float:
        """Return the wait until the soonest key cooldown expires."""
        if not self._cooldown_until:
            return 0.0
        return max(0.0, min(self._cooldown_until.values()) - time.time())

    def mark_exhausted(self, idx: int, cooldown_seconds: Optional[float] = None) -> None:
        cooldown = cooldown_seconds or self.DEFAULT_COOLDOWN_SECONDS
        self._cooldown_until[idx] = time.time() + cooldown
        logger.warning("Gemini key #%d rate-limited; cooling down for %.0fs.", idx + 1, cooldown)
        self._cursor = (idx + 1) % len(self._keys)

    def reset(self) -> None:
        """Clear all key cooldowns."""
        self._cooldown_until.clear()
        self._cursor = 0


class BaseAgent(ABC):
    """
    All agents inherit from this class to get consistent LLM access
    and error handling.
    """

    def __init__(self):
        self._gemini_pool: GeminiKeyPool | None = None
        self._groq   = None
        self._init_clients()

    def _init_clients(self):
        # ── Gemini client(s) ──────────────────────────────────────────────
        if config.GEMINI_API_KEYS:
            try:
                from google import genai as google_genai  # noqa: F401
                self._gemini_pool = GeminiKeyPool(config.GEMINI_API_KEYS)
            except ImportError:
                logger.warning("google-genai not installed; Gemini unavailable.")

        # ── Groq client ────────────────────────────────────────────────────
        if config.GROQ_API_KEY:
            try:
                from groq import Groq
                self._groq = Groq(api_key=config.GROQ_API_KEY)
            except ImportError:
                logger.warning("groq not installed; Groq/Llama unavailable.")

    # ── Gemini (Explorer / Evaluator) ──────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_not_exception_type(GeminiQuotaExhaustedError),
        reraise=True,
    )
    async def _gemini_generate(
        self,
        prompt: str,
        model: str | None = None,
        max_tokens: int = 2048,
    ) -> str:
        """
        Call Gemini and return the raw text response.
        Rotate to another configured key immediately on a rate-limit error.
        """
        if self._gemini_pool is None:
            raise RuntimeError("Gemini client not initialised. Check GEMINI_API_KEY(S).")

        model = model or config.EXPLORER_MODEL
        max_full_pool_waits = 3
        full_pool_waits = 0

        while True:
            current = self._gemini_pool.current()
            if current is None:
                full_pool_waits += 1
                if full_pool_waits > max_full_pool_waits:
                    raise GeminiQuotaExhaustedError(
                        f"All {len(config.GEMINI_API_KEYS)} configured Gemini key(s) "
                        f"are still rate-limited after {max_full_pool_waits} cooldown "
                        "cycles. This may indicate daily quota exhaustion."
                    )
                wait_seconds = self._gemini_pool.seconds_until_next_available() + 1
                logger.warning(
                    "All Gemini keys are cooling down; waiting %.0fs (%d/%d).",
                    wait_seconds, full_pool_waits, max_full_pool_waits,
                )
                await asyncio.sleep(wait_seconds)
                continue

            idx, client = current
            try:
                response = await client.aio.models.generate_content(
                    model=model,
                    contents=prompt,
                    config={"max_output_tokens": max_tokens, "temperature": 0.2},
                )
                return response.text
            except Exception as exc:
                if _is_rate_limit_error(exc):
                    self._gemini_pool.mark_exhausted(
                        idx, cooldown_seconds=_parse_retry_delay(exc)
                    )
                    continue
                raise

    # ── Groq (Mutator) ─────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=15),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    def _groq_generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str | None = None,
        max_tokens: int = 2048,
    ) -> str:
        """
        Call Groq (Llama / Qwen) and return the assistant text.
        Note: Groq's Python client is synchronous; run in executor if needed.
        """
        if self._groq is None:
            raise RuntimeError("Groq client not initialised. Check GROQ_API_KEY.")

        model = model or config.MUTATOR_MODEL
        response = self._groq.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.3,
        )
        return response.choices[0].message.content

    # ── JSON extraction ────────────────────────────────────────────────────────

    @staticmethod
    def _extract_json(text: str) -> Any:
        """
        Robustly extract the first JSON object or array from an LLM response,
        stripping markdown code fences if present.
        """
        # Strip ```json ... ``` or ``` ... ```
        text = re.sub(r"```(?:json)?\s*", "", text).strip().rstrip("`")

        # Try full parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Find the first { ... } or [ ... ] block
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = text.find(start_char)
            end   = text.rfind(end_char)
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(text[start: end + 1])
                except json.JSONDecodeError:
                    continue

        refusal_markers = (
            "i cannot assist", "i can't assist", "i am not able to",
            "i'm not able to", "i won't be able to", "i'm unable to",
        )
        if any(m in text.lower() for m in refusal_markers):
            logger.warning(
                "LLM appears to have REFUSED the request (safety/policy "
                "response) rather than returned malformed JSON — this is "
                "not the same as the model deciding there's nothing left "
                "to do: %s…", text[:200]
            )
        else:
            logger.warning("Could not extract JSON from LLM response: %s…", text[:200])
        return None
