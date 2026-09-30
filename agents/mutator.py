"""
agents/mutator.py — The Mutator Agent (Generator)

Responsibility:
  Analyse the captured API payloads and hypothesise malicious mutations
  that could reveal business-logic vulnerabilities.

  Vulnerability classes targeted (OWASP Top 10 / CWE):
    • IDOR / Broken Access Control  — CWE-639, CWE-284
    • Trust Boundary Violation      — CWE-501
    • Cart / Price Manipulation     — CWE-840
    • Privilege Escalation via role — CWE-269
    • Path Traversal in IDs         — CWE-22

Strategy:
  1. Pull candidate payloads from the VectorStore using semantic queries.
  2. For each candidate, use Groq (Llama 4 Scout) to generate a set of
     mutation hypotheses — LLM is great at creative fuzzing.
  3. Apply rule-based mutations as a deterministic safety net.
  4. Return a structured list of attack hypotheses for the Orchestrator.

Why Groq / Llama for this role?
  Speed.  The Mutator is called once per candidate endpoint — potentially
  dozens of times per scan.  Groq's ~750 tok/s throughput keeps total
  mutation time under 30 seconds even for large apps.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import re
import uuid
from typing import Any, Optional

from agents.base_agent import BaseAgent
from memory.vector_store import VectorStore

logger = logging.getLogger("Mutator")


# ── Prompt template ───────────────────────────────────────────────────────────

_MUTATION_SYSTEM_PROMPT = """
You are an expert penetration tester specialising in business-logic and
access-control vulnerabilities.

Given an intercepted API request, generate mutation hypotheses to test for:
  1. IDOR (Insecure Direct Object Reference) — swap resource IDs to access
     another user's data.
  2. Privilege escalation — add or modify role/admin fields.
  3. Price/quantity manipulation — alter financial values.
  4. Trust boundary violation — inject fields the server shouldn't trust
     from the client (e.g. setting server-side-only fields).

Output ONLY a JSON array (no markdown). Each element must be:
{{
  "vuln_type":        "<IDOR | PRIVILEGE_ESC | PRICE_MANIP | TRUST_VIOLATION>",
  "cwe_id":           "<e.g. CWE-639>",
  "description":      "<one-sentence hypothesis>",
  "mutated_payload":  {{<the complete modified JSON body>}},
  "field_changed":    "<name of the field that was mutated>",
  "expected_outcome": "<what the attacker hopes to observe if vulnerable>"
}}

Limit to 5 mutations per payload.  Avoid mutations that change the
fundamental structure of the request (only change VALUES, not shape).
"""

_MUTATION_USER_PROMPT = """
Endpoint:  {endpoint}
Method:    {method}
Original body (PII-scrubbed):
{body}

Generate mutations.
"""


# ── Deterministic mutation rules ──────────────────────────────────────────────

def _rule_based_mutations(
    endpoint: str, method: str, body: dict
) -> list[dict]:
    """
    Complement the LLM-generated mutations with deterministic rules.
    These always run, even if the LLM call fails.

    Returns a list of mutation dicts (same schema as LLM output).
    """
    mutations = []

    def mutate(field: str, old_val: Any, new_val: Any, vuln_type: str, cwe: str, desc: str):
        new_body = copy.deepcopy(body)
        _set_nested(new_body, field, new_val)
        mutations.append({
            "vuln_type":        vuln_type,
            "cwe_id":           cwe,
            "description":      desc,
            "mutated_payload":  new_body,
            "field_changed":    field,
            "expected_outcome": "Server returns data belonging to another resource.",
        })

    flat = _flatten(body)

    for key, val in flat.items():
        # ── Integer ID mutations (IDOR) ──────────────────────────────────
        if isinstance(val, int) and _looks_like_id_key(key):
            mutate(key, val, val + 1, "IDOR", "CWE-639",
                   f"Increment {key} by 1 to access adjacent resource")
            mutate(key, val, 1, "IDOR", "CWE-639",
                   f"Set {key}=1 — often maps to the first/admin record")

        # ── UUID mutations (IDOR) ────────────────────────────────────────
        if isinstance(val, str) and _is_uuid(val):
            mutate(key, val, "00000000-0000-0000-0000-000000000001", "IDOR", "CWE-639",
                   f"Replace UUID {key} with nil-adjacent ID (admin record probe)")

        # ── Price / quantity manipulation ────────────────────────────────
        if isinstance(val, (int, float)) and _looks_like_price_key(key):
            mutate(key, val, 0, "PRICE_MANIP", "CWE-840",
                   f"Set {key}=0 to attempt free item / zero-cost checkout")
            mutate(key, val, -1, "PRICE_MANIP", "CWE-840",
                   f"Set {key}=-1 to test negative-price credit injection")

        # ── Role / privilege escalation ──────────────────────────────────
        if isinstance(val, str) and _looks_like_role_key(key):
            mutate(key, val, "admin", "PRIVILEGE_ESC", "CWE-269",
                   f"Override {key}='admin' to escalate privileges")
        if isinstance(val, bool) and key.lower() in {"is_admin", "admin", "superuser"}:
            mutate(key, val, True, "PRIVILEGE_ESC", "CWE-269",
                   f"Flip {key} to True for privilege escalation")

    return mutations


# ── Helpers ───────────────────────────────────────────────────────────────────

"""
agents/mutator.py — The Mutator Agent (Generator)

Responsibility:
  Analyse the captured API payloads and hypothesise malicious mutations
  that could reveal business-logic vulnerabilities.

  Vulnerability classes targeted (OWASP Top 10 / CWE):
    • IDOR / Broken Access Control  — CWE-639, CWE-284
    • Trust Boundary Violation      — CWE-501
    • Cart / Price Manipulation     — CWE-840
    • Privilege Escalation via role — CWE-269
    • Path Traversal in IDs         — CWE-22

Strategy:
  1. Pull candidate payloads from the VectorStore using semantic queries.
  2. For each candidate, use Groq (Llama 4 Scout) to generate a set of
     mutation hypotheses — LLM is great at creative fuzzing.
  3. Apply rule-based mutations as a deterministic safety net.
  4. Return a structured list of attack hypotheses for the Orchestrator.

Why Groq / Llama for this role?
  Speed.  The Mutator is called once per candidate endpoint — potentially
  dozens of times per scan.  Groq's ~750 tok/s throughput keeps total
  mutation time under 30 seconds even for large apps.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import re
import uuid
from typing import Any, Optional

from agents.base_agent import BaseAgent
from memory.vector_store import VectorStore

logger = logging.getLogger("Mutator")


# ── Prompt template ───────────────────────────────────────────────────────────

_MUTATION_SYSTEM_PROMPT = """
You are an expert penetration tester specialising in business-logic and
access-control vulnerabilities.

Given an intercepted API request, generate mutation hypotheses to test for:
  1. IDOR (Insecure Direct Object Reference) — swap resource IDs to access
     another user's data.
  2. Privilege escalation — add or modify role/admin fields.
  3. Price/quantity manipulation — alter financial values.
  4. Trust boundary violation — inject fields the server shouldn't trust
     from the client (e.g. setting server-side-only fields).

Output ONLY a JSON array (no markdown). Each element must be:
{{
  "vuln_type":        "<IDOR | PRIVILEGE_ESC | PRICE_MANIP | TRUST_VIOLATION>",
  "cwe_id":           "<e.g. CWE-639>",
  "description":      "<one-sentence hypothesis>",
  "mutated_payload":  {{<the complete modified JSON body>}},
  "field_changed":    "<name of the field that was mutated>",
  "expected_outcome": "<what the attacker hopes to observe if vulnerable>"
}}

Limit to 5 mutations per payload.  Avoid mutations that change the
fundamental structure of the request (only change VALUES, not shape).
"""

_MUTATION_USER_PROMPT = """
Endpoint:  {endpoint}
Method:    {method}
Original body (PII-scrubbed):
{body}

Generate mutations.
"""


# ── Deterministic mutation rules ──────────────────────────────────────────────

def _rule_based_mutations(
    endpoint: str, method: str, body: dict
) -> list[dict]:
    """
    Complement the LLM-generated mutations with deterministic rules.
    These always run, even if the LLM call fails.

    Returns a list of mutation dicts (same schema as LLM output).
    """
    mutations = []

    def mutate(field: str, old_val: Any, new_val: Any, vuln_type: str, cwe: str, desc: str):
        new_body = copy.deepcopy(body)
        _set_nested(new_body, field, new_val)
        mutations.append({
            "vuln_type":        vuln_type,
            "cwe_id":           cwe,
            "description":      desc,
            "mutated_payload":  new_body,
            "field_changed":    field,
            "expected_outcome": "Server returns data belonging to another resource.",
        })

    flat = _flatten(body)

    for key, val in flat.items():
        # ── Integer ID mutations (IDOR) ──────────────────────────────────
        if isinstance(val, int) and _looks_like_id_key(key):
            mutate(key, val, val + 1, "IDOR", "CWE-639",
                   f"Increment {key} by 1 to access adjacent resource")
            mutate(key, val, 1, "IDOR", "CWE-639",
                   f"Set {key}=1 — often maps to the first/admin record")

        # ── UUID mutations (IDOR) ────────────────────────────────────────
        if isinstance(val, str) and _is_uuid(val):
            mutate(key, val, "00000000-0000-0000-0000-000000000001", "IDOR", "CWE-639",
                   f"Replace UUID {key} with nil-adjacent ID (admin record probe)")

        # ── Price / quantity manipulation ────────────────────────────────
        if isinstance(val, (int, float)) and _looks_like_price_key(key):
            mutate(key, val, 0, "PRICE_MANIP", "CWE-840",
                   f"Set {key}=0 to attempt free item / zero-cost checkout")
            mutate(key, val, -1, "PRICE_MANIP", "CWE-840",
                   f"Set {key}=-1 to test negative-price credit injection")

        # ── Role / privilege escalation ──────────────────────────────────
        if isinstance(val, str) and _looks_like_role_key(key):
            mutate(key, val, "admin", "PRIVILEGE_ESC", "CWE-269",
                   f"Override {key}='admin' to escalate privileges")
        if isinstance(val, bool) and key.lower() in {"is_admin", "admin", "superuser"}:
            mutate(key, val, True, "PRIVILEGE_ESC", "CWE-269",
                   f"Flip {key} to True for privilege escalation")

    return mutations


# ── Helpers ───────────────────────────────────────────────────────────────────

def _field_name(key: str) -> str:
    """
    Extract the matchable field name from a flattened key, stripping any
    trailing array-index suffix, e.g. "items[0].price" -> "price",
    "user_ids[2]" -> "user_ids".
    """
    return re.sub(r"\[\d+\]$", "", key.split(".")[-1])


def _singularized(name: str) -> str:
    """
    Naive singularisation so a scalar-array container like
    {"user_ids": [5, 6, 7]} still matches the singular pattern "user_id".
    Good enough for the plural shapes real APIs use, not a full stemmer.
    """
    if name.endswith("ies"):
        return name[:-3] + "y"
    if name.endswith("s") and not name.endswith("ss"):
        return name[:-1]
    return name


def _looks_like_id_key(key: str) -> bool:
    id_patterns = {"id", "user_id", "userid", "account_id", "order_id",
                   "resource_id", "owner_id", "profile_id", "customer_id",
                   "product_id", "item_id", "line_item_id"}
    name = _field_name(key).lower()
    return name in id_patterns or _singularized(name) in id_patterns


def _looks_like_price_key(key: str) -> bool:
    price_keys = {"price", "total", "amount", "quantity", "qty",
                  "cost", "subtotal", "discount", "unit_price"}
    name = _field_name(key).lower()
    return name in price_keys or _singularized(name) in price_keys


def _looks_like_role_key(key: str) -> bool:
    role_keys = {"role", "roles", "permission", "permissions",
                 "access_level", "privilege", "group"}
    name = _field_name(key).lower()
    return name in role_keys or _singularized(name) in role_keys


def _is_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except ValueError:
        return False


def _flatten(obj: Any, prefix: str = "") -> dict:
    """
    Recursively flatten a nested dict/list into {dotted.path: value} pairs.

    List items get an index suffix, e.g. "items[0].price", so cart/line-item
    arrays are visible to the mutation rules below — without this, a
    payload like {"items": [{"price": 9.99}]} never produced a
    PRICE_MANIP hypothesis at all.
    """
    result: dict = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            result.update(_flatten(v, full_key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            full_key = f"{prefix}[{i}]"
            result.update(_flatten(item, full_key))
    else:
        result[prefix] = obj
    return result


_PATH_SEGMENT_RE = re.compile(r"^([^\[\]]+)(?:\[(\d+)\])?$")


def _set_nested(d: dict, dotted_key: str, value: Any) -> None:
    """
    Set a value inside a nested dict/list structure using a dotted path
    with optional [i] array-index suffixes, e.g. "items[0].price" or
    "user.address.zip". Mirrors the path shape _flatten() produces above,
    so any key it reports can be written straight back into the payload.
    """
    segments = dotted_key.split(".")
    container = d

    for i, seg in enumerate(segments):
        m = _PATH_SEGMENT_RE.match(seg)
        name, idx = (seg, None) if not m else (m.group(1), m.group(2))
        idx = int(idx) if idx is not None else None
        is_last = i == len(segments) - 1

        if idx is None:
            # Plain dict key
            if is_last:
                container[name] = value
            else:
                container = container.setdefault(name, {})
        else:
            # Array-indexed key, e.g. items[0]
            lst = container.setdefault(name, [])
            while len(lst) <= idx:
                lst.append({})
            if is_last:
                lst[idx] = value
            else:
                container = lst[idx]


# ── Agent class ───────────────────────────────────────────────────────────────

class MutatorAgent(BaseAgent):
    """
    Phase 2: Attack hypothesis generation.

    Queries the VectorStore for interesting API payloads, then combines
    LLM creativity (Groq/Llama) with deterministic rules to produce a
    prioritised list of attack hypotheses.
    """

    def __init__(self, vector_store: VectorStore):
        super().__init__()
        self.vector_store = vector_store

    async def generate_hypotheses(self, max_hypotheses: int = 25) -> list[dict]:
        """
        Main entry point.  Returns a list of structured attack hypotheses.

        Each hypothesis:
        {
            "vuln_type":         str,
            "cwe_id":            str,
            "description":       str,
            "endpoint_pattern":  str,   # glob for route interception
            "method":            str,
            "original_payload":  dict,
            "malicious_payload": dict,
            "field_changed":     str,
            "expected_outcome":  str,
            "target_url":        str,   # page URL to navigate to before attack
            "trigger_ref":       None,  # populated by Orchestrator if needed
        }
        """
        all_hypotheses: list[dict] = []

        candidate_sets = [
            ("IDOR", self.vector_store.get_idor_candidates()),
            ("PRICE", self.vector_store.get_price_candidates()),
            ("ROLE",  self.vector_store.get_role_candidates()),
        ]

        for category, candidates in candidate_sets:
            logger.info(
                "Mutator: generating %s hypotheses for %d candidates",
                category, len(candidates)
            )
            for candidate in candidates:
                if len(all_hypotheses) >= max_hypotheses:
                    break

                hypotheses = await self._mutate_candidate(candidate)
                all_hypotheses.extend(hypotheses)

        logger.info("Mutator: generated %d total hypotheses.", len(all_hypotheses))
        return all_hypotheses[:max_hypotheses]

    async def _mutate_candidate(self, candidate: dict) -> list[dict]:
        """Generate mutations for a single candidate payload."""
        endpoint = candidate.get("endpoint", "")
        method   = candidate.get("method", "POST")
        body     = candidate.get("request_body", {})
        sanitised_body = candidate.get("sanitised_body", body)

        # ── LLM-generated mutations ────────────────────────────────────────
        llm_mutations = await self._llm_mutate(endpoint, method, sanitised_body)

        # ── Rule-based mutations (deterministic safety net) ────────────────
        rule_mutations = _rule_based_mutations(endpoint, method, body)

        # ── Merge and deduplicate by changed field ─────────────────────────
        seen_keys: set[str] = set()
        merged: list[dict] = []

        for mutation in (llm_mutations + rule_mutations):
            changed_field = mutation.get("field_changed", "?")
            key = f"{endpoint}::{changed_field}::{mutation.get('vuln_type')}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Annotate with endpoint info for the Orchestrator
            mutation.update({
                "endpoint_pattern": self._to_glob(endpoint),
                "method":           method,
                "original_payload": body,
                "target_url":       endpoint,   # Orchestrator may override
                "trigger_ref":      None,
            })
            merged.append(mutation)

        return merged

    async def _llm_mutate(
        self,
        endpoint: str,
        method: str,
        sanitised_body: dict,
    ) -> list[dict]:
        """
        Ask Groq / Llama to creatively generate mutations.
        Falls back to empty list if the LLM call fails.
        """
        import json
        user_prompt = _MUTATION_USER_PROMPT.format(
            endpoint=endpoint,
            method=method,
            body=json.dumps(sanitised_body, indent=2)[:1500],
        )
        try:
            # Run sync Groq client in a thread executor to avoid blocking
            raw = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._groq_generate(
                    system_prompt=_MUTATION_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    max_tokens=1500,
                )
            )
            parsed = self._extract_json(raw)
            if isinstance(parsed, list):
                return parsed
        except Exception as exc:
            logger.warning("LLM mutation failed for %s: %s", endpoint, exc)

        return []

    @staticmethod
    def _to_glob(url: str) -> str:
        """
        Convert a full URL to a Playwright route glob pattern.
        e.g. https://example.com/api/v1/profile?id=5
          →  **/api/v1/profile*
        """
        match = re.search(r"(https?://[^/]+)(.*?)(\?.*)?$", url)
        if match:
            path = match.group(2).rstrip("/")
            return f"**{path}*"
        return f"**{url}*"

def _singularized(name: str) -> str:
    """
    Naive singularisation so a scalar-array container like
    {"user_ids": [5, 6, 7]} still matches the singular pattern "user_id".
    Good enough for the plural shapes real APIs use, not a full stemmer.
    """
    if name.endswith("ies"):
        return name[:-3] + "y"
    if name.endswith("s") and not name.endswith("ss"):
        return name[:-1]
    return name

def _looks_like_id_key(key: str) -> bool:
    id_patterns = {"id", "user_id", "userid", "account_id", "order_id",
                   "resource_id", "owner_id", "profile_id", "customer_id",
                   "product_id", "item_id", "line_item_id"}
    name = _field_name(key).lower()
    return name in id_patterns or _singularized(name) in id_patterns


def _looks_like_price_key(key: str) -> bool:
    price_keys = {"price", "total", "amount", "quantity", "qty",
                  "cost", "subtotal", "discount", "unit_price"}
    name = _field_name(key).lower()
    return name in price_keys or _singularized(name) in price_keys


def _looks_like_role_key(key: str) -> bool:
    role_keys = {"role", "roles", "permission", "permissions",
                 "access_level", "privilege", "group"}
    name = _field_name(key).lower()
    return name in role_keys or _singularized(name) in role_keys


def _is_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except ValueError:
        return False


def _flatten(obj: Any, prefix: str = "") -> dict:
    """
    Recursively flatten a nested dict/list into {dotted.path: value} pairs.
 
    List items get an index suffix, e.g. "items[0].price", so cart/line-item
    arrays are visible to the mutation rules below — without this, a
    payload like {"items": [{"price": 9.99}]} never produced a
    PRICE_MANIP hypothesis at all.
    """
    result: dict = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            result.update(_flatten(v, full_key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            full_key = f"{prefix}[{i}]"
            result.update(_flatten(item, full_key))
    else:
        result[prefix] = obj
    return result

_PATH_SEGMENT_RE = re.compile(r"^([^\[\]]+)(?:\[(\d+)\])?$")

def _set_nested(d: dict, dotted_key: str, value: Any) -> None:
    """
    Set a value inside a nested dict/list structure using a dotted path
    with optional [i] array-index suffixes, e.g. "items[0].price" or
    "user.address.zip". Mirrors the path shape _flatten() produces above,
    so any key it reports can be written straight back into the payload.
    """
    segments = dotted_key.split(".")
    container = d
 
    for i, seg in enumerate(segments):
        m = _PATH_SEGMENT_RE.match(seg)
        name, idx = (seg, None) if not m else (m.group(1), m.group(2))
        idx = int(idx) if idx is not None else None
        is_last = i == len(segments) - 1
 
        if idx is None:
            # Plain dict key
            if is_last:
                container[name] = value
            else:
                container = container.setdefault(name, {})
        else:
            # Array-indexed key, e.g. items[0]
            lst = container.setdefault(name, [])
            while len(lst) <= idx:
                lst.append({})
            if is_last:
                lst[idx] = value
            else:
                container = lst[idx]

# ── Agent class ───────────────────────────────────────────────────────────────

class MutatorAgent(BaseAgent):
    """
    Phase 2: Attack hypothesis generation.

    Queries the VectorStore for interesting API payloads, then combines
    LLM creativity (Groq/Llama) with deterministic rules to produce a
    prioritised list of attack hypotheses.
    """

    def __init__(self, vector_store: VectorStore):
        super().__init__()
        self.vector_store = vector_store

    async def generate_hypotheses(self, max_hypotheses: int = 25) -> list[dict]:
        """
        Main entry point.  Returns a list of structured attack hypotheses.

        Each hypothesis:
        {
            "vuln_type":         str,
            "cwe_id":            str,
            "description":       str,
            "endpoint_pattern":  str,   # glob for route interception
            "method":            str,
            "original_payload":  dict,
            "malicious_payload": dict,
            "field_changed":     str,
            "expected_outcome":  str,
            "target_url":        str,   # page URL to navigate to before attack
            "trigger_ref":       None,  # populated by Orchestrator if needed
        }
        """
        all_hypotheses: list[dict] = []

        candidate_sets = [
            ("IDOR", self.vector_store.get_idor_candidates()),
            ("PRICE", self.vector_store.get_price_candidates()),
            ("ROLE",  self.vector_store.get_role_candidates()),
        ]

        for category, candidates in candidate_sets:
            logger.info(
                "Mutator: generating %s hypotheses for %d candidates",
                category, len(candidates)
            )
            for candidate in candidates:
                if len(all_hypotheses) >= max_hypotheses:
                    break

                hypotheses = await self._mutate_candidate(candidate)
                all_hypotheses.extend(hypotheses)

        logger.info("Mutator: generated %d total hypotheses.", len(all_hypotheses))
        return all_hypotheses[:max_hypotheses]

    async def _mutate_candidate(self, candidate: dict) -> list[dict]:
        """Generate mutations for a single candidate payload."""
        endpoint = candidate.get("endpoint", "")
        method   = candidate.get("method", "POST")
        body     = candidate.get("request_body", {})
        sanitised_body = candidate.get("sanitised_body", body)

        # ── LLM-generated mutations ────────────────────────────────────────
        llm_mutations = await self._llm_mutate(endpoint, method, sanitised_body)

        # ── Rule-based mutations (deterministic safety net) ────────────────
        rule_mutations = _rule_based_mutations(endpoint, method, body)

        # ── Merge and deduplicate by changed field ─────────────────────────
        seen_keys: set[str] = set()
        merged: list[dict] = []

        for mutation in (llm_mutations + rule_mutations):
            changed_field = mutation.get("field_changed", "?")
            key = f"{endpoint}::{changed_field}::{mutation.get('vuln_type')}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Annotate with endpoint info for the Orchestrator
            mutation.update({
                "endpoint_pattern": self._to_glob(endpoint),
                "method":           method,
                "original_payload": body,
                "target_url":       endpoint,   # Orchestrator may override
                "trigger_ref":      None,
            })
            merged.append(mutation)

        return merged

    async def _llm_mutate(
        self,
        endpoint: str,
        method: str,
        sanitised_body: dict,
    ) -> list[dict]:
        """
        Ask Groq / Llama to creatively generate mutations.
        Falls back to empty list if the LLM call fails.
        """
        import json
        user_prompt = _MUTATION_USER_PROMPT.format(
            endpoint=endpoint,
            method=method,
            body=json.dumps(sanitised_body, indent=2)[:1500],
        )
        try:
            # Run sync Groq client in a thread executor to avoid blocking
            raw = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._groq_generate(
                    system_prompt=_MUTATION_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    max_tokens=1500,
                )
            )
            parsed = self._extract_json(raw)
            if isinstance(parsed, list):
                return parsed
        except Exception as exc:
            logger.warning("LLM mutation failed for %s: %s", endpoint, exc)

        return []

    @staticmethod
    def _to_glob(url: str) -> str:
        """
        Convert a full URL to a Playwright route glob pattern.
        e.g. https://example.com/api/v1/profile?id=5
          →  **/api/v1/profile*
        """
        match = re.search(r"(https?://[^/]+)(.*?)(\?.*)?$", url)
        if match:
            path = match.group(2).rstrip("/")
            return f"**{path}*"
        return f"**{url}*"
