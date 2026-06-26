"""
agents/evaluator.py — The Evaluator Agent (Observer)

Responsibility:
  After a malicious payload is injected, the Evaluator reads the resulting
  DOM state and network responses to determine whether the attack succeeded.

  It is the difference between a *scanner* (flags potential issues) and a
  *verifier* (confirms exploitability with a PoC).

Verification heuristics used:
  • IDOR           — did the DOM or response expose data belonging to a
                     *different* user/resource than the current session owns?
  • Price manip    — did the server accept a zero/negative price?
  • Privilege esc  — did the UI reveal admin controls / elevated permissions?
  • Generic        — did the response status change from 4xx to 2xx after
                     mutation?  Does the response body contain unexpected PII?

Gemini 2.5 Flash is used here because evaluating success requires
understanding large DOM diffs with cross-page context.
"""

from __future__ import annotations

import json
import logging

from agents.base_agent import BaseAgent
from mcp_client import PlaywrightMCPClient

logger = logging.getLogger("Evaluator")


# ── Prompt templates ──────────────────────────────────────────────────────────

_EVALUATE_PROMPT = """
You are a penetration testing verification expert.

A security test just injected a malicious payload into a web application.
Your job is to determine whether the exploit was SUCCESSFUL.

═══ ATTACK DETAILS ═══
Vulnerability hypothesis: {vuln_type} ({cwe_id})
Description:              {description}
Endpoint:                 {endpoint}
Original payload:         {original_payload}
Malicious payload:        {malicious_payload}
Field changed:            {field_changed}
Expected outcome:         {expected_outcome}

═══ BEFORE ATTACK (DOM snapshot) ═══
{pre_snapshot}

═══ AFTER ATTACK (DOM snapshot) ═══
{post_snapshot}

═══ NETWORK RESPONSE (last 3 requests) ═══
{network_responses}

═══ EVALUATION CRITERIA ═══
Answer YES only if there is clear, unambiguous evidence that:
  - For IDOR: the response contains data clearly belonging to a DIFFERENT user
    or resource (different name, email, account number, etc.)
  - For PRICE_MANIP: the server accepted and confirmed a zero / negative price
  - For PRIVILEGE_ESC: the UI or response grants elevated permissions
  - For TRUST_VIOLATION: a server-side-only field was accepted and reflected
  - For any: the HTTP status changed from 4xx → 2xx AND content changed meaningfully

Do NOT mark as success if:
  - The page just looks similar (similarity ≠ data exposure)
  - You only see generic success messages without data
  - The status is still 4xx or the error is unchanged

Respond ONLY with a JSON object:
{{
  "success":   <true|false>,
  "confidence": <0.0 – 1.0>,
  "severity":  "<CRITICAL|HIGH|MEDIUM|LOW>",
  "evidence":  "<specific quoted text from DOM/response proving exploitability, or 'NONE'>",
  "reasoning": "<2-3 sentences explaining your verdict>"
}}
"""


# ── Severity mapping ──────────────────────────────────────────────────────────

_VULN_SEVERITY = {
    "IDOR":            "HIGH",
    "PRIVILEGE_ESC":   "CRITICAL",
    "PRICE_MANIP":     "HIGH",
    "TRUST_VIOLATION": "MEDIUM",
}


class EvaluatorAgent(BaseAgent):
    """
    Phase 3 (inner loop): Exploit verification.

    Called once per attack hypothesis to produce a binary success verdict
    plus supporting evidence for the final report.
    """

    def __init__(self, browser: PlaywrightMCPClient):
        super().__init__()
        self.browser = browser

    async def evaluate(
        self,
        hypothesis: dict,
        pre_snapshot: str,
        post_snapshot: str,
        network_requests: list[dict],
    ) -> dict:
        """
        Evaluate whether a completed attack was successful.

        Returns:
            {
              "success":    bool,
              "confidence": float,
              "severity":   str,
              "evidence":   str,
              "reasoning":  str,
            }
        """
        # ── Fast heuristic check (no LLM cost if obviously failed) ────────
        fast_result = self._heuristic_check(hypothesis, network_requests)
        if fast_result is not None and not fast_result:
            logger.debug("Heuristic: attack failed quickly — skipping LLM eval.")
            return {
                "success":    False,
                "confidence": 0.9,
                "severity":   "N/A",
                "evidence":   "NONE",
                "reasoning":  "Network response indicated failure (4xx or unchanged error).",
            }

        # ── LLM-based deep evaluation ──────────────────────────────────────
        network_summary = self._format_network_summary(network_requests)

        prompt = _EVALUATE_PROMPT.format(
            vuln_type=hypothesis.get("vuln_type", ""),
            cwe_id=hypothesis.get("cwe_id", ""),
            description=hypothesis.get("description", ""),
            endpoint=hypothesis.get("endpoint_pattern", ""),
            original_payload=json.dumps(hypothesis.get("original_payload", {}), indent=2)[:500],
            malicious_payload=json.dumps(hypothesis.get("malicious_payload", {}), indent=2)[:500],
            field_changed=hypothesis.get("field_changed", ""),
            expected_outcome=hypothesis.get("expected_outcome", ""),
            pre_snapshot=str(pre_snapshot)[:2000],
            post_snapshot=str(post_snapshot)[:2000],
            network_responses=network_summary,
        )

        try:
            raw = await self._gemini_generate(
                prompt, model=self._evaluator_model(), max_tokens=512
            )
            result = self._extract_json(raw)

            if isinstance(result, dict):
                # Ensure severity is set
                if not result.get("severity") or result["severity"] == "N/A":
                    default_sev = _VULN_SEVERITY.get(hypothesis.get("vuln_type", ""), "MEDIUM")
                    result["severity"] = default_sev if result.get("success") else "N/A"
                return result

        except Exception as exc:
            logger.error("Evaluator LLM call failed: %s", exc)

        # Safe default on failure
        return {
            "success":    False,
            "confidence": 0.0,
            "severity":   "N/A",
            "evidence":   "NONE",
            "reasoning":  "Evaluator error — could not determine outcome.",
        }

    # ── Heuristic pre-check ───────────────────────────────────────────────────

    def _heuristic_check(
        self,
        hypothesis: dict,
        network_requests: list[dict],
    ) -> bool | None:
        """
        Cheap heuristic: return False if the last response is clearly an error.
        Return None to indicate the LLM should decide.
        """
        if not network_requests:
            return None

        last = network_requests[-1]
        status = last.get("status", 0)

        # If the server returned an auth/not-found error, likely failed
        if status in {401, 403, 404, 422}:
            return False

        # If status is 2xx, worth LLM analysis
        if 200 <= status < 300:
            return None

        return None

    # ── Response formatting ───────────────────────────────────────────────────

    @staticmethod
    def _format_network_summary(requests: list[dict]) -> str:
        """Format the last 3 network requests as a compact readable summary."""
        lines = []
        for req in requests[-3:]:
            status  = req.get("status", "?")
            method  = req.get("method", "?")
            url     = req.get("url", "?")[-80:]   # truncate long URLs
            resp    = str(req.get("responseBody", ""))[:300]
            lines.append(f"[{status}] {method} {url}\n  Response: {resp}")
        return "\n\n".join(lines) or "No network requests captured."

    @staticmethod
    def _evaluator_model() -> str:
        from config import config
        return config.EVALUATOR_MODEL
