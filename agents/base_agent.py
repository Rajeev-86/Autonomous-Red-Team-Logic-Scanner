"""
agents/base_agent.py — Abstract Base Agent

Provides shared infrastructure for all three swarm agents:
  - Gemini client (Explorer, Evaluator)
  - Groq client (Mutator)
  - Exponential back-off wrapper for rate limits
  - Structured JSON extraction from LLM responses
"""

from __future__ import annotations

import json
import logging
import re
from abc import ABC
from typing import Any

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from config import config

logger = logging.getLogger("BaseAgent")


class BaseAgent(ABC):
    """
    All agents inherit from this class to get consistent LLM access
    and error handling.
    """

    def __init__(self):
        self._gemini = None
        self._groq   = None
        self._init_clients()

    def _init_clients(self):
        # ── Gemini client ──────────────────────────────────────────────────
        if config.GEMINI_API_KEY:
            try:
                from google import genai as google_genai
                self._gemini = google_genai.Client(api_key=config.GEMINI_API_KEY)
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
        retry=retry_if_exception_type(Exception),
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
        Retries up to 3× with exponential back-off on errors.
        """
        if self._gemini is None:
            raise RuntimeError("Gemini client not initialised. Check GEMINI_API_KEY.")

        model = model or config.EXPLORER_MODEL
        response = await self._gemini.aio.models.generate_content(
            model=model,
            contents=prompt,
            config={"max_output_tokens": max_tokens, "temperature": 0.2},
        )
        return response.text

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
