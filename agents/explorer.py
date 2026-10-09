"""
agents/explorer.py — The Explorer Agent (Planner)

Responsibility:
  Passively map the target application by navigating it like a real user.
  For every view it visits, it:
    1. Captures an accessibility-tree snapshot (200-400 tokens per page)
    2. Uses Gemini to summarise the page and identify interactive elements
    3. Logs the view as a node in the StateGraph
    4. Captures any API traffic and stores payloads in the VectorStore
    5. Follows links / clicks buttons to explore deeper

This is the "happy-path" phase — no attacks are launched here.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Optional

from agents.base_agent import BaseAgent
from memory.state_graph import StateGraph, ViewNode, ActionEdge
from memory.vector_store import VectorStore
from mcp_client import PlaywrightMCPClient

logger = logging.getLogger("Explorer")


# ── Prompt templates ──────────────────────────────────────────────────────────

_SUMMARISE_PAGE_PROMPT = """
You are a QA engineer cataloguing the functionality of a web application
you have permission to test.
Below is the accessibility tree snapshot of a web page.
Respond with ONLY a JSON object (no markdown):

{{
  "page_summary": "<1-2 sentences describing the page's purpose>",
  "is_authenticated": <true|false>,
  "interactive_elements": [
    {{
      "ref":    "<accessibility ref, e.g. e12>",
      "type":   "button|link|input|select|form",
      "label":  "<human-readable label>",
      "value":  "<current value if input, else null>",
      "priority": <1-5, where 5 = most interesting to test next>
    }}
  ],
  "notes": "<anything noteworthy about this page's functionality>"
}}

Accessibility tree:
{snapshot}
"""

_PICK_NEXT_ACTION_PROMPT = """
You are cataloguing the functionality of a web application you have
permission to test, by clicking through it like a QA engineer would.
You have already visited these URLs:
{visited_urls}

Current page summary: {page_summary}
Available interactive elements:
{elements}

Pick the SINGLE most useful next action to cover functionality you
haven't explored yet.
Respond with ONLY a JSON object:
{{
  "action":    "click|type|navigate|done",
  "ref":       "<element ref, if click/type>",
  "text":      "<text to type, if action is type>",
  "url":       "<URL to navigate to, if action is navigate>",
  "reasoning": "<one-sentence justification>"
}}
Return {{"action": "done"}} when you've covered the available functionality
or reached the step limit.
"""


class ExplorerAgent(BaseAgent):
    """
    Phase 1: Passive application mapping.

    Navigates the target, builds the state graph, and populates
    the vector store with intercepted API payloads.
    """

    def __init__(
        self,
        browser: PlaywrightMCPClient,
        state_graph: StateGraph,
        vector_store: VectorStore,
    ):
        super().__init__()
        self.browser      = browser
        self.state_graph  = state_graph
        self.vector_store = vector_store
        self._visited_urls: set[str] = set()
        self._current_node_id: Optional[str] = None

    # ── Main exploration loop ──────────────────────────────────────────────────

    async def map_application(self, target_url: str, max_steps: int = 50) -> None:
        """
        Entry point: navigate *target_url* and explore up to *max_steps* actions.

        Populates self.state_graph and self.vector_store as side-effects.
        """
        logger.info("Starting exploration of %s (max %d steps)", target_url, max_steps)

        await self.browser.navigate(target_url)
        await self.browser.wait_for_load()

        for step in range(max_steps):
            current_url = await self.browser.get_current_url()
            logger.debug("[Step %d] URL: %s", step + 1, current_url)

            # ── Snapshot & analyse current view ───────────────────────────
            snapshot   = await self.browser.snapshot()
            page_data  = await self._analyse_page(snapshot)

            if not page_data:
                logger.warning("Gemini returned no page data — skipping step.")
                continue

            # ── Capture network traffic ────────────────────────────────────
            network_requests = await self.browser.get_network_requests()
            await self._ingest_network_requests(network_requests, snapshot)

            # ── Add / update node in state graph ───────────────────────────
            fingerprint = hashlib.sha256(snapshot.encode()).hexdigest()[:16]
            node = ViewNode(
                url=current_url,
                dom_summary=page_data.get("page_summary", ""),
                session_state={"is_authenticated": page_data.get("is_authenticated")},
                structural_fingerprint=fingerprint,
            )
            new_node_id = self.state_graph.add_node(node)

            self._visited_urls.add(current_url)
            self._current_node_id = new_node_id

            # ── Decide next action ─────────────────────────────────────────
            action = await self._pick_next_action(
                page_summary=page_data.get("page_summary", ""),
                elements=page_data.get("interactive_elements", []),
            )

            if not action or action.get("action") == "done":
                logger.info("Explorer: done signal at step %d.", step + 1)
                break

            logger.debug(
                "[Step %d] action=%s ref=%s text=%s url=%s reasoning=%s",
                step + 1, action.get("action"), action.get("ref"),
                action.get("text"), action.get("url"), action.get("reasoning"),
            )

            prev_node_id = new_node_id
            await self._execute_action(action, page_data.get("interactive_elements", []))
            await self.browser.wait_for_load(timeout_ms=2000)

            # Include same-URL structural changes such as SPA dialogs.
            new_url = await self.browser.get_current_url()
            new_snapshot = await self.browser.snapshot()
            new_fingerprint = hashlib.sha256(new_snapshot.encode()).hexdigest()[:16]
            target_node = ViewNode(
                url=new_url,
                dom_summary="",
                session_state={},
                structural_fingerprint=new_fingerprint,
            )
            target_id = self.state_graph.add_node(target_node)

            if target_id != prev_node_id:
                edge = ActionEdge(
                    source_id=prev_node_id,
                    target_id=target_id,
                    action_type=action.get("action", "click"),
                    action_ref=action.get("ref", action.get("url", "")),
                    payload={},
                )
                try:
                    self.state_graph.add_edge(edge)
                except ValueError:
                    pass  # nodes not in graph yet — skip

        logger.info(
            "Exploration complete. %s", self.state_graph.summary()
        )

    # ── LLM helpers ───────────────────────────────────────────────────────────

    async def _analyse_page(self, snapshot: str) -> Optional[dict]:
        """Use Gemini to summarise the current page and extract elements."""
        prompt = _SUMMARISE_PAGE_PROMPT.format(snapshot=snapshot[:6000])
        try:
            raw = await self._gemini_generate(prompt, model=self.config_model())
            return self._extract_json(raw)
        except Exception as exc:
            logger.error("Page analysis failed: %s", exc)
            return None

    async def _pick_next_action(
        self,
        page_summary: str,
        elements: list[dict],
    ) -> Optional[dict]:
        """Use Gemini to decide the next navigation action."""
        # Filter elements already explored or low priority
        candidates = sorted(
            [e for e in elements if e.get("priority", 0) >= 2],
            key=lambda e: -e.get("priority", 0),
        )[:10]

        prompt = _PICK_NEXT_ACTION_PROMPT.format(
            visited_urls="\n".join(sorted(self._visited_urls)[-20:]),
            page_summary=page_summary,
            elements=str(candidates),
        )
        try:
            raw = await self._gemini_generate(prompt, model=self.config_model())
            return self._extract_json(raw)
        except Exception as exc:
            logger.error("Next-action selection failed: %s", exc)
            return None

    async def _execute_action(self, action: dict, elements: list[dict]) -> None:
        """Dispatch a parsed action dict to the MCP browser client."""
        atype = action.get("action")
        
        def _get_element_label(ref: str) -> str:
            for e in elements:
                if e.get("ref") == ref:
                    return e.get("label") or e.get("type") or ""
            return ""

        if atype == "click":
            ref = action.get("ref", "")
            if ref:
                await self.browser.click(ref, _get_element_label(ref))

        elif atype == "type":
            ref  = action.get("ref", "")
            text = action.get("text", "")
            if ref and text:
                await self.browser.type_text(ref, text, _get_element_label(ref))

        elif atype == "navigate":
            url = action.get("url", "")
            if url:
                await self.browser.navigate(url)

        # Brief pause between actions to avoid overwhelming the app
        await asyncio.sleep(0.5)

    # ── Network ingestion ──────────────────────────────────────────────────────

    async def _ingest_network_requests(
        self,
        requests: list[dict],
        dom_context: str,
    ) -> None:
        """
        Parse intercepted network requests and store interesting API calls
        in the VectorStore for later Mutator analysis.

        Only stores JSON API calls (ignores static assets, images, etc.).
        """
        for req in requests:
            url     = req.get("url", "")
            method  = req.get("method", "GET")
            body    = req.get("requestBody") or req.get("body") or {}
            status  = req.get("status", 0)
            resp    = req.get("responseBody", "")

            # Skip non-API traffic (static assets, analytics, CDN, etc.)
            if not self._is_api_call(url, method, body):
                continue

            if isinstance(body, str):
                try:
                    import json
                    body = json.loads(body)
                except Exception:
                    body = {"raw": body}

            doc_id = self.vector_store.add_request(
                endpoint=url,
                method=method,
                request_body=body if isinstance(body, dict) else {},
                response_status=status,
                response_body=resp[:500] if isinstance(resp, str) else "",
                dom_context=dom_context[:300],
            )
            logger.debug("Ingested API payload → %s (%s)", url, doc_id)

    @staticmethod
    def _is_api_call(url: str, method: str, body: any) -> bool:
        """Heuristic: is this request an interesting JSON API call?"""
        # Skip static assets
        skip_extensions = (".js", ".css", ".png", ".jpg", ".ico", ".woff", ".svg")
        if any(url.endswith(ext) for ext in skip_extensions):
            return False
        # Skip analytics / CDN
        skip_domains = ("google-analytics", "hotjar", "cdn.", "fonts.", "sentry")
        if any(d in url for d in skip_domains):
            return False
        # Prefer mutating methods or calls with a body
        return method in {"POST", "PUT", "PATCH", "DELETE"} or bool(body)

    @staticmethod
    def config_model() -> str:
        from config import config
        return config.EXPLORER_MODEL
