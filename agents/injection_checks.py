"""
agents/injection_checks.py — Deterministic XSS / SQL-injection probes.

Unlike IDOR/PRICE/ROLE verification (agents/evaluator.py), which needs an
LLM to judge whether a DOM diff represents a meaningful business-logic
breach, these two checks have crisp, mechanical signals that don't
benefit from — and shouldn't be left to — fuzzy LLM judgment:
  - XSS:  did OUR OWN unique injected marker get parsed as live markup?
  - SQLi: does a response contain a real database/ORM error signature,
          or did a classic auth-bypass payload actually authenticate us?

No Gemini/Groq call is made anywhere in this module, so it has none of
the token-truncation, expired-key, or wrong-model-name failure modes
that have hit the rest of this pipeline — it only ever touches the
browser.
"""

from __future__ import annotations

import re
import uuid
from typing import Optional

from mcp_client import PlaywrightMCPClient

# ── XSS ──────────────────────────────────────────────────────────────────

def make_xss_payload() -> tuple[str, str]:
    """
    Build a unique, inert XSS canary payload and the marker to look for.

    Deliberately NOT alert(1) or similar: a real blocking JS dialog would
    hang headless Playwright waiting for a prompt that never gets
    dismissed. A harmless <img> with a unique data-attribute is enough
    proof the browser parsed our input as markup rather than text — the
    attribute is queryable via the DOM regardless of whether "x" ever
    loads as an image.
    """
    marker = uuid.uuid4().hex[:12]
    payload = f'<img src=x data-xss-canary="{marker}">'
    return payload, marker


async def check_xss_reflected(browser: PlaywrightMCPClient, marker: str) -> bool:
    """
    True if our canary marker exists as a real DOM attribute right now —
    meaning the browser parsed our injected string as markup, not text.
    A correctly-escaping app would only ever render the marker inside a
    text node, which this selector can never match.
    """
    found = await browser.evaluate_js(
        f'!!document.querySelector(\'[data-xss-canary="{marker}"]\')'
    )
    return bool(found)


# ── SQL injection ────────────────────────────────────────────────────────

SQLI_AUTH_BYPASS_PAYLOAD = "' OR 1=1--"
SQLI_ERROR_PROBE_PAYLOAD = "'"

_LOGIN_FIELD_HINTS    = ("email", "username", "user name", "login id", "login")
_PASSWORD_FIELD_HINTS = ("password",)

# Deliberately not SQLite-only, even though Juice Shop itself runs on
# SQLite — these are universal driver/ORM error signatures, not app-
# specific keywords, so this check generalises to other targets the way
# the id/price/role field-name keyword lists (which ARE inherently
# app-shaped business logic) never fully can.
_SQL_ERROR_RE = re.compile(
    r"SQLITE_ERROR|SQLITE_CONSTRAINT|SqliteError|sqlite3\.OperationalError|"
    r"ER_PARSE_ERROR|ER_BAD_FIELD_ERROR|MySqlError|"
    r"PostgresError|invalid input syntax for|"
    r"SequelizeDatabaseError|SequelizeValidationError|"
    r"unrecognized token|near \"[^\"]*\": syntax error",
    re.IGNORECASE,
)


def looks_like_login_field(label: str) -> bool:
    label = (label or "").lower()
    return any(h in label for h in _LOGIN_FIELD_HINTS)


def looks_like_password_field(label: str) -> bool:
    label = (label or "").lower()
    return any(h in label for h in _PASSWORD_FIELD_HINTS)


def check_sql_error_signature(network_requests: list[dict]) -> Optional[str]:
    """Return the matched DB/ORM error string if any response contains one."""
    for req in network_requests:
        resp = req.get("responseBody", "")
        if not isinstance(resp, str):
            continue
        m = _SQL_ERROR_RE.search(resp)
        if m:
            return m.group(0)
    return None


def check_auth_bypass_success(network_requests: list[dict]) -> Optional[dict]:
    """
    Return the login request/response dict if a login-shaped POST came
    back 200 with what looks like an issued auth token — i.e. the app
    authenticated us despite a payload that was never a valid password.
    """
    for req in network_requests:
        url = req.get("url", "")
        if "login" not in url.lower():
            continue
        if req.get("method") != "POST":
            continue
        if req.get("status") != 200:
            continue
        resp = req.get("responseBody", "")
        if isinstance(resp, str) and '"token"' in resp:
            return req
    return None