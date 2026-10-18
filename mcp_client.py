"""
mcp_client.py — Async wrapper around the Microsoft Playwright MCP server.

The Playwright MCP server is a Node.js process started with:
    npx @playwright/mcp@latest --headless

This client connects to it over stdio using the official Python MCP SDK,
exposing high-level browser automation primitives to the agent swarm.

Reference: https://github.com/microsoft/playwright-mcp
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from config import config

logger = logging.getLogger("MCPClient")


class PlaywrightMCPClient:
    """
    Async context manager that manages the lifetime of a Playwright MCP
    server subprocess and exposes typed helper methods for each tool.

    Usage:
        async with PlaywrightMCPClient() as browser:
            await browser.navigate("https://juice-shop.example.com")
            snapshot = await browser.snapshot()
    """

    # browser_network_requests renders lines like:
    #   "7. [POST] http://localhost:3000/rest/basket/6/checkout => [200] OK"
    #   "3. [GET] http://localhost:3000/rest/products"                (pending)
    #   "9. [GET] http://localhost:3000/socket.io => [FAILED] net::ERR_..."
    _REQUEST_LINE_RE = re.compile(
        r"^(\d+)\.\s*\[(\w+)\]\s*(\S+)(?:\s*=>\s*\[(\d+|FAILED)\]\s*(.*))?\s*$"
    )

    def __init__(self, headless: bool = True):
        self.headless = headless
        self._session: Optional[ClientSession] = None
        self._stdio_ctx = None
        self._session_ctx = None
        self._next_request_index = 1  # watermark: only process new requests

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "PlaywrightMCPClient":
        args = list(config.MCP_ARGS)
        if not self.headless and "--headless" in args:
            args.remove("--headless")

        server_params = StdioServerParameters(
            command=config.MCP_COMMAND,
            args=args,
        )

        self._stdio_ctx = stdio_client(server_params)
        read, write = await self._stdio_ctx.__aenter__()

        self._session_ctx = ClientSession(read, write)
        self._session = await self._session_ctx.__aenter__()
        await self._session.initialize()

        logger.info("Playwright MCP server ready.")
        return self

    async def __aexit__(self, *args):
        if self._session_ctx:
            await self._session_ctx.__aexit__(*args)
        if self._stdio_ctx:
            await self._stdio_ctx.__aexit__(*args)
        logger.info("Playwright MCP server shut down.")

    # ── Core Browser Actions ──────────────────────────────────────────────────

    async def navigate(self, url: str) -> dict:
        """Navigate to a URL and return the new page state."""
        result = await self._call("browser_navigate", {"url": url})
        # The server's own navigate() handler calls _clearCollectedArtifacts(),
        # which zeroes its per-tab _requests array on every navigation —
        # confirmed in the real v0.0.83 source. Our index watermark has to
        # reset in lockstep, or every request on every page after the first
        # permanently looks "already seen" and gets silently dropped.
        self._next_request_index = 1
        return result

    async def snapshot(self) -> str:
        """
        Return the current page accessibility tree as a compact text snapshot.
        ~200-400 tokens — far cheaper than a screenshot for LLM reasoning.
        """
        result = await self._call("browser_snapshot", {})
        return result if isinstance(result, str) else json.dumps(result)

    async def click(self, ref: str, element: str = "") -> dict:
        """
        Click an element identified by its accessibility ref (e.g. 'e12').

        The wire parameter is "target", not "ref" — confirmed directly
        against this server's own schema via list_tools() (v0.0.83). "ref"
        doesn't exist in this version's schema at all; every prior attempt
        using it failed Zod validation with "expected string, received
        undefined → at target", which is exactly what we were seeing.
        """
        return await self._call("browser_click", {"target": ref, "element": element})

    async def type_text(self, ref: str, text: str, element: str = "", submit: bool = False) -> dict:
        """Type text into an input field. Optionally press Enter to submit."""
        return await self._call("browser_type", {"target": ref, "text": text, "element": element, "submit": submit})

    async def select_option(self, ref: str, value: str, element: str = "") -> dict:
        """Select a dropdown option by value."""
        return await self._call("browser_select_option", {"target": ref, "values": [value], "element": element})

    async def get_current_url(self) -> str:
        """Return the URL currently loaded in the browser."""
        result = await self.evaluate_js("window.location.href")
        return result if isinstance(result, str) else str(result or "")

    async def wait_for_load(self, timeout_ms: int = 3000) -> None:
        """Approximate network idle with a capped fixed-time wait."""
        seconds = max(0.1, min(10, timeout_ms / 1000))
        await self._call("browser_wait_for", {"time": seconds})

    # ── Network Interception ──────────────────────────────────────────────────

    async def get_network_requests(self) -> list[dict]:
        """
        Return network requests captured SINCE THE LAST call to this method,
        as clean dicts: {url, method, status, requestBody, responseBody}.

        browser_network_requests does NOT return JSON — confirmed against
        the real v0.0.83 server source. It returns a numbered, human-
        readable text listing, and bodies aren't included in it at all;
        each one requires a SEPARATE browser_network_request call with an
        index + part ("request-body"/"response-body"). This method does
        both steps so callers keep getting the plain dict shape they
        already expect.
        """
        raw = await self._call("browser_network_requests", {})
        text = raw if isinstance(raw, str) else json.dumps(raw)

        parsed: list[dict] = []
        for line in text.splitlines():
            m = self._REQUEST_LINE_RE.match(line.strip())
            if not m:
                continue  # header line, trailing "Note: N static..." line, etc.
            index_s, method, url, status_s, _status_text = m.groups()
            index = int(index_s)
            if index < self._next_request_index:
                continue  # already handled on a previous step
            parsed.append({
                "index": index,
                "url": url,
                "method": method,
                "status": int(status_s) if status_s and status_s.isdigit() else 0,
                "requestBody": None,
                "responseBody": "",
            })

        if not parsed:
            return []

        self._next_request_index = max(r["index"] for r in parsed) + 1

        # Fetching a body is a whole extra round trip per request, so only
        # pay for it on things that actually look like API calls.
        for req in parsed:
            if not self._looks_like_api_call(req["url"], req["method"]):
                continue
            try:
                body = await self._call(
                    "browser_network_request",
                    {"index": req["index"], "part": "request-body"},
                )
                if isinstance(body, str) and body.strip():
                    req["requestBody"] = self._strip_heading(body)
            except Exception as exc:
                logger.debug("No request body for #%d: %s", req["index"], exc)
            try:
                resp = await self._call(
                    "browser_network_request",
                    {"index": req["index"], "part": "response-body"},
                )
                if isinstance(resp, str):
                    req["responseBody"] = self._strip_heading(resp)
            except Exception as exc:
                logger.debug("No response body for #%d: %s", req["index"], exc)

        return parsed

    @staticmethod
    def _looks_like_api_call(url: str, method: str) -> bool:
        skip_ext = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
            ".ico", ".woff", ".woff2", ".svg", ".map",
        )
        path = url.split("?", 1)[0]
        if any(path.endswith(ext) for ext in skip_ext):
            return False
        return (
            method in {"POST", "PUT", "PATCH", "DELETE"}
            or "/rest/" in url
            or "/api/" in url
        )

    @staticmethod
    def _strip_heading(text: str) -> str:
        """Some MCP tool responses prepend a '### <title>' line before the
        real content (confirmed for browser_snapshot's 'Page'/'Snapshot'
        sections and browser_network_request's 'Request body'/'Response
        body' sections — _call()'s regex only strips a literal '### Result'
        header, so these pass through untouched otherwise)."""
        if text.startswith("###"):
            _, _, rest = text.partition("\n")
            return rest
        return text

    async def route_intercept_and_modify(
        self,
        url_pattern: str,
        modified_body: dict,
        method: str = "POST",
    ) -> dict:
        """
        Register a route mock on *url_pattern*. Matching requests get the
        response body replaced with *modified_body*.

        This is the core primitive for IDOR and business-logic testing —
        equivalent to Burp Suite's Repeater tab, but automated.

        ⚠️  AUTHORIZED USE ONLY. Only intercept requests on systems you
            have written permission to test.

        Args:
            url_pattern: Glob or regex pattern matching the endpoint
                         (e.g. '**/api/v1/profile*').
            modified_body: The malicious payload dict to substitute.
                method: Kept for the caller's/report's benefit only. The browser
                    route tool mocks every request matching the pattern.

        Returns:
            Confirmation dict or text from the MCP server.
        """
        return await self._call("browser_route", {
            "pattern":     url_pattern,
            "body":        json.dumps(modified_body),
            "contentType": "application/json",
            "status":      200,          # Let it through — backend decides fate
        })

    async def clear_routes(self) -> None:
        """Remove all active route mocks."""
        await self._call("browser_unroute", {})

    # ── Utilities ─────────────────────────────────────────────────────────────

    async def evaluate_js(self, expression: str) -> Any:
        """
        Execute a single JS expression in page context and return the result.

        browser_evaluate's real parameter is "function" (not "script"), and
        it must be a JS function expression — e.g. "() => 1 + 1", not a bare
        "1 + 1". We do that wrapping here so callers can keep passing plain
        expressions.
        """
        result = await self._call(
            "browser_evaluate", {"function": f"() => {expression}"}
        )
        # Some MCP responses wrap the value as {"result": ...}; others — e.g.
        # when the evaluated JS returns a plain object — ARE the value
        # itself, with no wrapper. Only unwrap when a "result" key is
        # actually present, so a JS-returned object isn't mistaken for a
        # wrapper and emptied out via .get("result") -> None.
        if isinstance(result, dict) and "result" in result:
            return result["result"]
        return result

    async def get_cookies(self) -> list[dict]:
        """Return all cookies for the current origin (session tokens, CSRF, etc.)."""
        return await self.evaluate_js(
            "document.cookie.split(';').map(c => c.trim())"
        ) or []

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _call(self, tool_name: str, args: dict) -> Any:
        """
        Invoke a Playwright MCP tool and parse the response.

        The MCP server returns content blocks; we extract the first text block
        and attempt JSON parsing, falling back to raw string.
        """
        if self._session is None:
            raise RuntimeError("MCPClient not entered — use 'async with' context.")

        try:
            result = await self._session.call_tool(tool_name, args)
        except Exception as exc:
            logger.error("MCP tool call failed: %s(%s) → %s", tool_name, args, exc)
            raise

        if not result or not result.content:
            return {}

        raw = result.content[0]
        text = getattr(raw, "text", None) or str(raw)

        if getattr(result, "isError", False):
            logger.error("MCP tool error: %s(%s) → %s", tool_name, args, text)
            raise RuntimeError(f"MCP tool '{tool_name}' returned an error: {text}")

        match = re.search(r"###\s*Result\s*\n(.*?)(?:\n###\s|\Z)", text, re.DOTALL)
        if match:
            text = match.group(1).strip()

        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text