"""
config.py — Central configuration for the Red Team Logic Scanner.

All secrets come from environment variables (or a .env file).
Never hard-code API keys.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # ── LLM API Keys ──────────────────────────────────────────────────────────
    GEMINI_API_KEY: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    GROQ_API_KEY:   str = field(default_factory=lambda: os.getenv("GROQ_API_KEY",   ""))

    # Optional: multiple Gemini keys for round-robin on rate limits, e.g.
    #   GEMINI_API_KEYS=key_from_project_a,key_from_project_b
    # Note: Gemini free-tier rate limits are enforced PER GOOGLE CLOUD
    # PROJECT, not per API key — multiple keys from the SAME project share
    # one quota pool and this will not add any capacity. Each key here needs
    # to come from a genuinely separate project. Falls back to [GEMINI_API_KEY].
    GEMINI_API_KEYS: List[str] = field(default_factory=lambda: [
        key.strip() for key in os.getenv("GEMINI_API_KEYS", "").split(",") if key.strip()
    ] or ([os.getenv("GEMINI_API_KEY", "")] if os.getenv("GEMINI_API_KEY") else []))

    # ── Model Selection ───────────────────────────────────────────────────────
    # Explorer & Evaluator — high-context DOM reasoning
    EXPLORER_MODEL:  str = "gemini-3.5-flash-lite"
    EVALUATOR_MODEL: str = "gemini-3.5-flash-lite"
    # Mutator — high-throughput payload generation via Groq free tier
    MUTATOR_MODEL: str = "meta-llama/llama-4-scout-17b-16e-instruct"   # or "qwen/qwen3-32b"

    # ── Semantic Memory ───────────────────────────────────────────────────────
    CHROMA_PERSIST_DIR: str = "./data/chroma_db"
    COLLECTION_NAME:    str = "api_payloads"

    # ── State Graph ───────────────────────────────────────────────────────────
    SQLITE_DB_PATH: str = "./data/state_graph.db"

    # ── Playwright MCP Server ─────────────────────────────────────────────────
    MCP_COMMAND: str       = "npx"
    MCP_ARGS: List[str]    = field(default_factory=lambda: [
    "@playwright/mcp@latest", "--headless", "--no-sandbox",
    "--caps=network",   # exposes browser_route / browser_unroute — required
                        # for payload injection; not enabled by default
    ])

    # ── Scanner Behaviour ─────────────────────────────────────────────────────
    TARGET_URL:            str   = ""
    MAX_EXPLORE_STEPS:     int   = 50
    MAX_ATTACK_ATTEMPTS:   int   = 25
    SIMILARITY_THRESHOLD:  float = 0.72   # cosine sim threshold for vector recall

    # ── Output ────────────────────────────────────────────────────────────────
    REPORT_PATH: str = "./reports/findings.json"

    # ── Privacy ───────────────────────────────────────────────────────────────
    # When True, SHA-256-hash any value that looks like PII before sending
    # to external LLM APIs (email, phone, SSN patterns).
    HASH_PII: bool = True

    def validate(self):
        """Raise early if critical config is missing."""
        missing = []
        if not self.GEMINI_API_KEYS:
            missing.append("GEMINI_API_KEY (or GEMINI_API_KEYS)")
        if not self.GROQ_API_KEY:
            missing.append("GROQ_API_KEY")
        if not self.TARGET_URL:
            missing.append("TARGET_URL")
        if missing:
            raise EnvironmentError(
                f"Missing required config: {', '.join(missing)}\n"
                "Set them in a .env file or as environment variables."
            )


config = Config()
