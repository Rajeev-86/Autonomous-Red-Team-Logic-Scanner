"""
main.py — CLI entrypoint for the Red Team Logic Scanner

Usage:
    python main.py --target http://localhost:3000
    python main.py --target https://juice-shop.example.com --explore 75 --attacks 30
    python main.py --target http://localhost:3000 --visible   # headed browser
    python main.py --target http://localhost:3000 --export-graph

⚠️  AUTHORISED TESTING ONLY.
    Use against OWASP Juice Shop, DVWA, WebGoat, or systems you own / have
    written permission to test.  Attacking systems without authorisation is
    illegal in virtually every jurisdiction.
"""

import argparse
import asyncio
import logging
import sys

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="red-team-scanner",
        description="Autonomous AI swarm for business-logic vulnerability detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target http://localhost:3000
  python main.py --target http://juice-shop.local --explore 100 --attacks 50
  python main.py --target http://localhost:3000 --visible --export-graph

Authorised test targets:
  OWASP Juice Shop  →  docker run -p 3000:3000 bkimminich/juice-shop
  WebGoat           →  docker run -p 8080:8080 webgoat/goat-and-wolf
  DVWA              →  docker run -p 8081:80 vulnerables/web-dvwa
        """,
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Base URL of the target application.",
    )
    parser.add_argument(
        "--explore",
        type=int, default=50,
        help="Max exploration steps for the Explorer agent (default: 50).",
    )
    parser.add_argument(
        "--attacks",
        type=int, default=25,
        help="Max attack hypotheses to test (default: 25).",
    )
    parser.add_argument(
        "--visible",
        action="store_true",
        help="Run browser in headed (visible) mode — useful for debugging.",
    )
    parser.add_argument(
        "--export-graph",
        action="store_true",
        help="Export the state graph to reports/state_graph.json after scan.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity (default: INFO).",
    )
    parser.add_argument(
        "--report",
        default="./reports/findings.json",
        help="Output path for the JSON findings report.",
    )

    return parser.parse_args()


async def main() -> int:
    args = parse_args()

    # ── Logging ────────────────────────────────────────────────────────────────
    logging.basicConfig(
        level=args.log_level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("chromadb").setLevel(logging.WARNING)

    # ── Apply CLI overrides to config ──────────────────────────────────────────
    from config import config
    config.TARGET_URL          = args.target
    config.MAX_EXPLORE_STEPS   = args.explore
    config.MAX_ATTACK_ATTEMPTS = args.attacks
    config.REPORT_PATH         = args.report

    if args.visible:
        config.MCP_ARGS = ["@playwright/mcp@latest"]   # remove --headless

    # ── Validate config ────────────────────────────────────────────────────────
    try:
        config.validate()
    except EnvironmentError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        return 1

    # ── Run scan ───────────────────────────────────────────────────────────────
    from orchestrator import RedTeamOrchestrator

    orchestrator = RedTeamOrchestrator(target_url=args.target)

    try:
        findings = await orchestrator.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        findings = orchestrator.confirmed_vulns

    # ── Save report ────────────────────────────────────────────────────────────
    report = orchestrator.save_report()

    # ── Optional state graph export ────────────────────────────────────────────
    if args.export_graph:
        import os, json
        os.makedirs("reports", exist_ok=True)
        graph_path = "reports/state_graph.json"
        with open(graph_path, "w") as f:
            f.write(orchestrator.state_graph.export_json())
        console.print(f"State graph exported → [cyan]{graph_path}[/cyan]")

    return 0 if not findings else 2   # exit 2 = findings present


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
