"""
orchestrator.py — Tri-Agent Swarm Orchestrator

Manages the full lifecycle of a red-team scan:

  Phase 1 ▸ Explorer  — passive application mapping
  Phase 2 ▸ Mutator   — attack hypothesis generation
  Phase 3 ▸ Attack    — active payload injection + Evaluator verification

All confirmed vulnerabilities include the full HTTP request/response PoC
chain (equivalent to a Burp Suite export) for developer reproduction.

⚠️  IMPORTANT:
    This tool is for AUTHORISED security testing only.
    Only run against systems you own or have written permission to test.
    Typical authorised targets: OWASP Juice Shop, DVWA, WebGoat,
    your own staging environment, or a dedicated bug-bounty scope.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import print as rprint

from config import config
from mcp_client import PlaywrightMCPClient
from memory.state_graph import StateGraph
from memory.vector_store import VectorStore
from agents.explorer import ExplorerAgent
from agents.mutator import MutatorAgent
from agents.evaluator import EvaluatorAgent
from agents.injection_checks import (
    make_xss_payload, check_xss_reflected,
    SQLI_AUTH_BYPASS_PAYLOAD, SQLI_ERROR_PROBE_PAYLOAD,
    check_sql_error_signature, check_auth_bypass_success,
    looks_like_login_field, looks_like_password_field,
)

logger  = logging.getLogger("Orchestrator")
console = Console()


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class HttpRecord:
    """A single captured HTTP request/response pair (PoC evidence)."""
    url:           str
    method:        str
    request_body:  dict
    status:        int
    response_body: str


@dataclass
class Vulnerability:
    """A confirmed, exploitable vulnerability with full PoC."""
    vuln_type:        str
    cwe_id:           str
    endpoint:         str
    description:      str
    severity:         str
    confidence:       float
    original_payload: dict
    malicious_payload: dict
    field_changed:    str
    evidence:         str
    reasoning:        str
    timestamp:        str
    http_chain:       List[HttpRecord] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["http_chain"] = [asdict(r) for r in self.http_chain]
        return d


# ── Orchestrator ──────────────────────────────────────────────────────────────

class RedTeamOrchestrator:
    """
    Coordinates the Explorer → Mutator → Evaluator swarm.

    Usage:
        orchestrator = RedTeamOrchestrator(target_url="http://localhost:3000")
        findings = await orchestrator.run()
        orchestrator.save_report()
    """

    def __init__(self, target_url: str):
        self.target_url       = target_url
        self.state_graph      = StateGraph()
        self.vector_store     = VectorStore()
        self.confirmed_vulns: List[Vulnerability] = []
        self._scan_start      = datetime.now(timezone.utc).isoformat()

    async def run(self) -> List[Vulnerability]:
        """
        Execute the full scan.  Returns list of confirmed vulnerabilities.
        """
        console.rule("[bold red]🔴 Red Team Logic Scanner")
        rprint(f"  [cyan]Target :[/cyan] {self.target_url}")
        rprint(f"  [cyan]Started:[/cyan] {self._scan_start}")
        console.print()

        async with PlaywrightMCPClient(headless=True) as browser:
            # ── Phase 1: Exploration ───────────────────────────────────────
            console.rule("[bold blue]Phase 1 — Passive Exploration")
            explorer = ExplorerAgent(browser, self.state_graph, self.vector_store)

            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                          console=console) as progress:
                task = progress.add_task(
                    f"Mapping application (max {config.MAX_EXPLORE_STEPS} steps)…"
                )
                await explorer.map_application(
                    self.target_url, config.MAX_EXPLORE_STEPS
                )
                progress.update(task, completed=True)

            graph_summary = self.state_graph.summary()
            rprint(f"  [green]✓[/green] Mapped {graph_summary['nodes']} views, "
                   f"{graph_summary['edges']} edges, "
                   f"{self.vector_store.count()} API payloads captured.")
            console.print()

            # ── Phase 2: Hypothesis Generation ────────────────────────────
            console.rule("[bold yellow]Phase 2 — Hypothesis Generation (Mutator)")
            mutator = MutatorAgent(self.vector_store)

            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                          console=console) as progress:
                task = progress.add_task(
                    f"Generating attack hypotheses (max {config.MAX_ATTACK_ATTEMPTS})…"
                )
                hypotheses = await mutator.generate_hypotheses(config.MAX_ATTACK_ATTEMPTS)
                progress.update(task, completed=True)

            rprint(f"  [green]✓[/green] {len(hypotheses)} hypotheses generated.")
            self._print_hypotheses_summary(hypotheses)
            console.print()

            # ── Phase 3: Active Attack Loop ────────────────────────────────
            console.rule("[bold red]Phase 3 — Active Attack & Verification")
            evaluator = EvaluatorAgent(browser)

            for i, hypothesis in enumerate(hypotheses, 1):
                desc  = hypothesis.get("description", "")[:60]
                vtype = hypothesis.get("vuln_type", "")
                rprint(f"  [{i}/{len(hypotheses)}] [yellow]{vtype}[/yellow] — {desc}…")

                result = await self._execute_attack(browser, evaluator, hypothesis)

                if result:
                    self.confirmed_vulns.append(result)
                    rprint(
                        f"    [bold red]🚨 CONFIRMED [{result.severity}]:"
                        f" {result.cwe_id} at {result.endpoint}[/bold red]"
                    )
                    rprint(f"    Evidence: {result.evidence[:100]}…")
                else:
                    rprint(f"    [dim]✗ Not exploitable[/dim]")

            # ── Phase 4: Injection Testing (XSS / SQLi) ─────────────────────
            console.rule("[bold magenta]Phase 4 — Injection Testing (XSS / SQLi)")

            pages = list(explorer.page_inputs.items())[:config.MAX_INJECTION_PAGES]
            rprint(
                f"  Testing {len(pages)} page(s) with discovered input fields "
                f"(up to {config.MAX_FIELDS_PER_PAGE} field(s) each)…"
            )

            for page_url, inputs in pages:
                fields = inputs[:config.MAX_FIELDS_PER_PAGE]

                for inp in fields:
                    ref, label = inp.get("ref"), inp.get("label", "")
                    if not ref:
                        continue

                    result = await self._test_xss(browser, page_url, ref, label)
                    if result:
                        self.confirmed_vulns.append(result)
                        rprint(
                            f"    [bold red]🚨 CONFIRMED [{result.severity}]:"
                            f" {result.cwe_id} at {result.endpoint}[/bold red]"
                        )
                    else:
                        rprint(f"    [dim]✗ XSS not reflected — {label or ref}[/dim]")

                    result = await self._test_sql_error(browser, page_url, ref, label)
                    if result:
                        self.confirmed_vulns.append(result)
                        rprint(
                            f"    [bold red]🚨 CONFIRMED [{result.severity}]:"
                            f" {result.cwe_id} at {result.endpoint}[/bold red]"
                        )
                    else:
                        rprint(f"    [dim]✗ No SQL error signature — {label or ref}[/dim]")

                # Auth-bypass only makes sense once per page, on whatever
                # looks like the login-shaped field, paired with a
                # password-shaped field if one's present alongside it.
                login_field = next(
                    (i for i in fields if looks_like_login_field(i.get("label", ""))),
                    None,
                )
                if login_field and login_field.get("ref"):
                    password_field = next(
                        (i for i in fields if looks_like_password_field(i.get("label", ""))),
                        None,
                    )
                    result = await self._test_sql_auth_bypass(
                        browser, page_url, login_field, password_field
                    )
                    if result:
                        self.confirmed_vulns.append(result)
                        rprint(
                            f"    [bold red]🚨 CONFIRMED [{result.severity}]:"
                            f" {result.cwe_id} at {result.endpoint}[/bold red]"
                        )
                    else:
                        rprint(
                            f"    [dim]✗ Auth bypass failed — "
                            f"{login_field.get('label', '')}[/dim]"
                        )

        # ── Final summary ──────────────────────────────────────────────────
        self._print_final_summary()
        return self.confirmed_vulns

    # ── Attack execution ──────────────────────────────────────────────────────

    async def _execute_attack(
        self,
        browser: PlaywrightMCPClient,
        evaluator: EvaluatorAgent,
        hypothesis: dict,
    ) -> Optional[Vulnerability]:
        """
        Execute one attack hypothesis:
          1. Navigate to the target page
          2. Capture pre-attack DOM state
          3. Register route intercept with malicious payload
          4. Trigger the UI action (or let natural navigation fire the request)
          5. Capture post-attack state + network responses
          6. Ask Evaluator for verdict
        """
        try:
            target_url = hypothesis.get("target_url", self.target_url)

            # Navigate to the page that fires the API call
            await browser.navigate(target_url)
            await browser.wait_for_load()

            # Capture baseline state
            pre_snapshot = await browser.snapshot()

            mutated_endpoint = hypothesis.get("mutated_endpoint")
            if mutated_endpoint:
                # URL-path IDOR (e.g. /api/Products/1 -> /api/Products/2):
                # there's no body to intercept — the different URL IS the
                # attack, body is unchanged — so route_intercept_and_modify
                # would be a no-op here. Fetch the mutated URL for real
                # instead of mocking a response on the original one.
                await browser.navigate(mutated_endpoint)
            else:
                # Register the route intercept with the mutated payload
                await browser.route_intercept_and_modify(
                    url_pattern=hypothesis.get("endpoint_pattern", "**/*"),
                    modified_body=hypothesis.get("malicious_payload", {}),
                    method=hypothesis.get("method", "POST"),
                )

                # Trigger the action if we have a UI ref; otherwise reload fires it
                trigger_ref = hypothesis.get("trigger_ref")
                if trigger_ref:
                    await browser.click(trigger_ref)
                else:
                    # Re-navigate to trigger the API call naturally
                    await browser.navigate(target_url)

            await browser.wait_for_load(timeout_ms=3000)

            # Capture post-attack state
            post_snapshot     = await browser.snapshot()
            network_requests  = await browser.get_network_requests()

            # Build HttpRecord chain for the report
            http_chain = self._http_chain_from(network_requests)

            # Ask Evaluator
            verdict = await evaluator.evaluate(
                hypothesis=hypothesis,
                pre_snapshot=pre_snapshot,
                post_snapshot=post_snapshot,
                network_requests=network_requests,
            )

            # Clean up intercepts for the next test
            await browser.clear_routes()

            if verdict.get("success"):
                return Vulnerability(
                    vuln_type=hypothesis["vuln_type"],
                    cwe_id=hypothesis.get("cwe_id", ""),
                    endpoint=hypothesis.get("mutated_endpoint")
                             or hypothesis.get("endpoint_pattern", ""),
                    description=hypothesis.get("description", ""),
                    severity=verdict.get("severity", "HIGH"),
                    confidence=verdict.get("confidence", 0.0),
                    original_payload=hypothesis.get("original_payload", {}),
                    malicious_payload=hypothesis.get("malicious_payload", {}),
                    field_changed=hypothesis.get("field_changed", ""),
                    evidence=verdict.get("evidence", ""),
                    reasoning=verdict.get("reasoning", ""),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    http_chain=http_chain,
                )

        except Exception as exc:
            logger.error(
                "Attack execution error for %s: %s",
                hypothesis.get("endpoint_pattern"), exc
            )
            try:
                await browser.clear_routes()
            except Exception:
                pass

        return None

    # ── Injection testing (Phase 4) ─────────────────────────────────────────
    # These three probes are intentionally simple and self-contained: each
    # re-navigates to a clean copy of its page before acting, rather than
    # reusing whatever state a previous probe left behind, so a messy
    # result on one field/payload can't bleed into the next. None of them
    # touch route_intercept_and_modify, _blacklisted_refs, or any Explorer
    # state — Phase 4 only ever reads explorer.page_inputs, never writes
    # back to it, so it can't disturb Phase 1-3's already-working behaviour.

    async def _test_xss(
        self, browser: PlaywrightMCPClient, page_url: str, ref: str, label: str,
    ) -> Optional[Vulnerability]:
        try:
            await browser.navigate(page_url)
            await browser.wait_for_load()

            payload, marker = make_xss_payload()
            await browser.type_text(ref, payload, label, submit=True)
            await browser.wait_for_load(timeout_ms=2000)

            if not await check_xss_reflected(browser, marker):
                return None

            network_requests = await browser.get_network_requests()
            return Vulnerability(
                vuln_type="XSS",
                cwe_id="CWE-79",
                endpoint=page_url,
                description=f"Unescaped HTML injection reflected via {label or ref!r}",
                severity="HIGH",
                confidence=0.9,
                original_payload={"field": label or ref, "value": ""},
                malicious_payload={"field": label or ref, "value": payload},
                field_changed=label or ref,
                evidence=(
                    f"Injected marker {marker!r} exists as a live DOM "
                    f"attribute after submission — the payload was parsed "
                    f"as markup, not rendered as escaped text."
                ),
                reasoning=(
                    "document.querySelector found the canary element; a "
                    "correctly-escaping app would never expose it as a "
                    "real attribute."
                ),
                timestamp=datetime.now(timezone.utc).isoformat(),
                http_chain=self._http_chain_from(network_requests),
            )
        except Exception as exc:
            logger.error("XSS probe error on %s (ref=%s): %s", page_url, ref, exc)
            return None

    async def _test_sql_error(
        self, browser: PlaywrightMCPClient, page_url: str, ref: str, label: str,
    ) -> Optional[Vulnerability]:
        try:
            await browser.navigate(page_url)
            await browser.wait_for_load()

            await browser.type_text(ref, SQLI_ERROR_PROBE_PAYLOAD, label, submit=True)
            await browser.wait_for_load(timeout_ms=2000)

            network_requests = await browser.get_network_requests()
            signature = check_sql_error_signature(network_requests)
            if not signature:
                return None

            return Vulnerability(
                vuln_type="SQLI",
                cwe_id="CWE-89",
                endpoint=page_url,
                description=f"Unhandled SQL error from a single quote in {label or ref!r}",
                severity="CRITICAL",
                confidence=0.85,
                original_payload={"field": label or ref, "value": ""},
                malicious_payload={"field": label or ref, "value": SQLI_ERROR_PROBE_PAYLOAD},
                field_changed=label or ref,
                evidence=f"Response contains a raw database error: {signature!r}",
                reasoning=(
                    "A single unescaped quote broke the underlying SQL "
                    "query and the resulting driver/ORM error reached the "
                    "client — this input is reaching the database without "
                    "parameterisation."
                ),
                timestamp=datetime.now(timezone.utc).isoformat(),
                http_chain=self._http_chain_from(network_requests),
            )
        except Exception as exc:
            logger.error("SQLi error-probe failed on %s (ref=%s): %s", page_url, ref, exc)
            return None

    async def _test_sql_auth_bypass(
        self,
        browser: PlaywrightMCPClient,
        page_url: str,
        login_field: dict,
        password_field: Optional[dict],
    ) -> Optional[Vulnerability]:
        try:
            await browser.navigate(page_url)
            await browser.wait_for_load()

            # Fill a dummy password alongside the payload where one exists:
            # the classic ' OR 1=1-- bypass only works because it comments
            # out the rest of the WHERE clause, so a password field left
            # empty could fail client-side validation before the request
            # ever fires at all, for reasons unrelated to the actual check.
            if password_field and password_field.get("ref"):
                await browser.type_text(
                    password_field["ref"], "irrelevant-value",
                    password_field.get("label", ""),
                )

            await browser.type_text(
                login_field["ref"], SQLI_AUTH_BYPASS_PAYLOAD,
                login_field.get("label", ""), submit=True,
            )
            await browser.wait_for_load(timeout_ms=2000)

            network_requests = await browser.get_network_requests()
            hit = check_auth_bypass_success(network_requests)
            if not hit:
                return None

            return Vulnerability(
                vuln_type="SQLI",
                cwe_id="CWE-89",
                endpoint=page_url,
                description="Authentication bypassed via SQL injection in login field",
                severity="CRITICAL",
                confidence=0.9,
                original_payload={"field": login_field.get("label", ""), "value": ""},
                malicious_payload={
                    "field": login_field.get("label", ""),
                    "value": SQLI_AUTH_BYPASS_PAYLOAD,
                },
                field_changed=login_field.get("label", "") or login_field.get("ref", ""),
                evidence=(
                    f"Login POST to {hit.get('url', '')} returned 200 with "
                    f"an issued auth token despite a payload that was "
                    f"never a valid password."
                ),
                reasoning=(
                    "The ' OR 1=1-- payload comments out the rest of the "
                    "SQL WHERE clause, so the password check never "
                    "actually runs — any value in the password field is "
                    "accepted."
                ),
                timestamp=datetime.now(timezone.utc).isoformat(),
                http_chain=self._http_chain_from(network_requests),
            )
        except Exception as exc:
            logger.error("SQLi auth-bypass probe failed on %s: %s", page_url, exc)
            return None

    @staticmethod
    def _http_chain_from(network_requests: list[dict]) -> List[HttpRecord]:
        return [
            HttpRecord(
                url=r.get("url", ""),
                method=r.get("method", ""),
                request_body=RedTeamOrchestrator._parse_body(r.get("requestBody")),
                status=r.get("status", 0),
                response_body=str(r.get("responseBody", ""))[:500],
            )
            for r in network_requests[-3:]
        ]

    # ── Reporting ─────────────────────────────────────────────────────────────

    def save_report(self) -> dict:
        """
        Save all findings to a JSON file.

        The JSON structure is designed to be compatible with OWASP benchmark
        output format and importable into Burp Suite's reporting workflow.
        """
        os.makedirs(os.path.dirname(config.REPORT_PATH), exist_ok=True)

        report = {
            "tool":            "Red Team Logic Scanner (Tri-Agent Swarm)",
            "scan_target":     self.target_url,
            "scan_start":      self._scan_start,
            "scan_end":        datetime.now(timezone.utc).isoformat(),
            "state_graph":     self.state_graph.summary(),
            "total_payloads":  self.vector_store.count(),
            "total_confirmed": len(self.confirmed_vulns),
            "severity_counts": self._severity_counts(),
            "findings":        [v.to_dict() for v in self.confirmed_vulns],
        }

        with open(config.REPORT_PATH, "w") as f:
            json.dump(report, f, indent=2)

        logger.info("Report saved → %s", config.REPORT_PATH)
        return report

    # ── Display helpers ───────────────────────────────────────────────────────

    def _print_hypotheses_summary(self, hypotheses: list[dict]) -> None:
        table = Table(title="Generated Hypotheses", show_lines=False)
        table.add_column("Vuln Type",  style="yellow")
        table.add_column("CWE",        style="cyan")
        table.add_column("Field",      style="magenta")
        table.add_column("Endpoint",   style="dim")
        for h in hypotheses[:15]:
            table.add_row(
                h.get("vuln_type", ""),
                h.get("cwe_id", ""),
                h.get("field_changed", ""),
                h.get("endpoint_pattern", "")[-50:],
            )
        if len(hypotheses) > 15:
            table.add_row("…", "", "", f"({len(hypotheses) - 15} more)")
        console.print(table)

    def _print_final_summary(self) -> None:
        console.rule("[bold green]Scan Complete")
        counts = self._severity_counts()
        rprint(f"\n  Confirmed findings: [bold]{len(self.confirmed_vulns)}[/bold]")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            n = counts.get(sev, 0)
            if n:
                colour = {"CRITICAL": "red", "HIGH": "orange3",
                          "MEDIUM": "yellow", "LOW": "green"}[sev]
                rprint(f"    [{colour}]{sev}[/{colour}]: {n}")
        rprint(f"\n  Report → [cyan]{config.REPORT_PATH}[/cyan]\n")

    def _severity_counts(self) -> dict:
        counts: dict = {}
        for v in self.confirmed_vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    @staticmethod
    def _parse_body(body) -> dict:
        if isinstance(body, dict):
            return body
        if isinstance(body, str):
            try:
                return json.loads(body)
            except (json.JSONDecodeError, TypeError):
                return {"raw": body}
        return {}