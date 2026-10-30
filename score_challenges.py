#!/usr/bin/env python3
"""
score_challenges.py — Objective pass/fail scorecard against OWASP Juice
Shop's own documented, numbered challenge list.

Why this exists: this scanner's own report says "CONFIRMED" when its
Evaluator judges something exploitable — but that's our tool's opinion
of itself. Juice Shop ships an independent, authoritative ground truth
instead: data/static/challenges.yml, exposed live at GET /api/Challenges
with a "solved": true/false flag per challenge, set by the app's OWN
internal detection logic — not by anything we report ourselves. This
script checks that ground truth directly, for exactly the challenges
this scanner's current mutation primitives (ID swap, price/qty
zero-out, role flip, XSS canary, SQLi error-signature/auth-bypass) are
structurally capable of triggering at all. Every key below was verified
directly against the real challenges.yml source (not inferred from a
naming convention) — a wrong key string would make this script
silently check nothing and always report "false", which is worse than
not having a scorer at all.

Usage:
    python score_challenges.py --target http://localhost:3000
    python score_challenges.py --target http://localhost:3000 --report ./reports/scan_report.json

IMPORTANT — solved status is CUMULATIVE for the life of the Juice Shop
instance, not scoped to "since your last scan". If you run this
scorer, then run it again later against the SAME long-lived instance
without restarting it, a challenge showing solved=True could be from
any scan you've ever run against it, not necessarily your most recent
one. Restart/recreate the Juice Shop container between scans if you
want each run's result to be independently meaningful, rather than
"has this EVER been triggered at least once, across every scan so far".
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# Every key here was confirmed directly against the real
# data/static/challenges.yml — see the module docstring for why that
# matters. "status" is our own honest read of where each one stands,
# not something Juice Shop reports.
TARGET_CHALLENGES = {
    "localXssChallenge": {
        "name": "DOM XSS",
        "difficulty": 1,
        "status": "Proven — this is the search-box finding confirmed "
                  "multiple times across recent scans.",
    },
    "basketAccessChallenge": {
        "name": "View Basket",
        "difficulty": 2,
        "status": "Built (URL-path IDOR swap on /rest/basket/{id}) but "
                  "never tested — explorer has never completed an "
                  "add-to-basket flow in any scan so far.",
    },
    "basketManipulateChallenge": {
        "name": "Manipulate Basket",
        "difficulty": 3,
        "status": "Built (basket_id body-field IDOR), same gap as above.",
    },
    "forgedFeedbackChallenge": {
        "name": "Forged Feedback",
        "difficulty": 3,
        "status": "Theoretically in scope (user-id field on a feedback "
                  "POST) — unconfirmed, needs a captured feedback "
                  "submission with that field present.",
    },
    "forgedReviewChallenge": {
        "name": "Forged Review",
        "difficulty": 3,
        "status": "Same shape as Forged Feedback — unconfirmed.",
    },
    "negativeOrderChallenge": {
        "name": "Payback Time",
        "difficulty": 3,
        "status": "PRICE_MANIP territory (negative price/quantity at "
                  "checkout) — needs checkout completed, unconfirmed.",
    },
    "loginAdminChallenge": {
        "name": "Login Admin",
        "difficulty": 2,
        "status": "Exactly what the SQLi auth-bypass probe targets — "
                  "attempted on login-shaped fields every scan, never "
                  "succeeded yet.",
    },
    "errorHandlingChallenge": {
        "name": "Error Handling",
        "difficulty": 1,
        "status": "Possible bonus overlap: the SQLi error-signature "
                  "probe (a single quote causing an unhandled DB error) "
                  "may satisfy this incidentally.",
    },
}


def fetch_challenges(target_url: str) -> list[dict]:
    """GET {target_url}/api/Challenges and return the raw challenge list."""
    url = target_url.rstrip("/") + "/api/Challenges"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    # Confirmed shape, direct from Juice Shop's own docs:
    # {"status": "success", "data": [ {...challenge...}, ... ]}
    return payload.get("data", [])


def load_own_findings(report_path: Optional[str]) -> list[dict]:
    """Best-effort: load this tool's own report.json, if given/present."""
    if not report_path:
        return []
    path = Path(report_path)
    if not path.exists():
        return []
    try:
        with path.open() as f:
            report = json.load(f)
        return report.get("findings", [])
    except Exception as exc:
        print(f"  (could not read {report_path}: {exc})", file=sys.stderr)
        return []


def summarise_own_findings(findings: list[dict]) -> str:
    """
    Loose, clearly-labelled context only — never authoritative. The
    live Juice Shop 'solved' flag is the real signal; this is just
    "what did our own report claim", shown side by side so a mismatch
    (we claimed it, Juice Shop disagrees, or vice versa) is visible
    rather than silently assumed away.
    """
    if not findings:
        return "no findings in our own report"
    by_type: dict = {}
    for f in findings:
        vt = f.get("vuln_type", "?")
        by_type[vt] = by_type.get(vt, 0) + 1
    return ", ".join(f"{n}x {vt}" for vt, n in sorted(by_type.items()))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score a Juice Shop instance's live challenge state "
                    "against this scanner's in-scope target list."
    )
    parser.add_argument("--target", "-t", required=True,
                         help="Base URL of the Juice Shop instance.")
    parser.add_argument("--report", "-r", default=None,
                         help="Path to this tool's own scan_report.json, "
                              "for side-by-side context (optional).")
    parser.add_argument("--history-file", default="./reports/challenge_history.jsonl",
                         help="Append a scored summary here each run, to "
                              "track results across repeated scans.")
    args = parser.parse_args()

    try:
        challenges = fetch_challenges(args.target)
    except urllib.error.URLError as exc:
        print(f"Could not reach {args.target}/api/Challenges: {exc}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Response from /api/Challenges wasn't valid JSON: {exc}")
        sys.exit(1)

    by_key = {c.get("key"): c for c in challenges if c.get("key")}
    own_findings = load_own_findings(args.report)

    print(f"Target: {args.target}")
    print(f"Live challenges fetched: {len(challenges)}")
    print(f"Our own report findings: {summarise_own_findings(own_findings)}")
    print()
    print(f"{'Challenge':<22} {'*':<3} {'Juice Shop says':<16} Notes")
    print("-" * 100)

    solved_keys = []
    for key, meta in TARGET_CHALLENGES.items():
        live = by_key.get(key)
        if live is None:
            status = "NOT FOUND"  # wrong key, or this version lacks it
        elif live.get("solved"):
            status = "SOLVED"
            solved_keys.append(key)
        else:
            status = "not solved"
        print(f"{meta['name']:<22} {meta['difficulty']:<3} {status:<16} {meta['status']}")

    solved_count = len(solved_keys)
    total = len(TARGET_CHALLENGES)
    print()
    print(f"Score: {solved_count}/{total} in-scope targets solved "
          f"(live, per Juice Shop's own state — not our own report's claims)")

    # NOTE: cumulative for the instance's lifetime — see module
    # docstring. This trend only means "per-run success rate" if you
    # restart/recreate the Juice Shop instance between scans.
    history_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": args.target,
        "solved_count": solved_count,
        "total_targets": total,
        "solved_keys": solved_keys,
    }
    history_path = Path(args.history_file)
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with history_path.open("a") as f:
        f.write(json.dumps(history_entry) + "\n")
    print(f"\nAppended to {history_path} "
          f"(remember: cumulative unless you reset the instance between runs)")


if __name__ == "__main__":
    main()