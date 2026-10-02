# 🔴 Red Team Logic Scanner — Tri-Agent Swarm

Autonomous AI agent swarm for detecting **business-logic vulnerabilities** that
traditional static scanners (SAST) and basic DAST tools miss.

> ⚠️ **Authorised testing only.** Use against systems you own or have explicit
> written permission to test. Unauthorised use is illegal.

---

## Architecture

```
Target App
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Playwright MCP Server  (Node.js / Chromium)            │
│  microsoft/playwright-mcp  ─── stdio ──►  Python         │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────┐   ┌──────────────────────┐
│  Phase 1: EXPLORER            │   │  StateGraph           │
│  Model: Gemini 2.5 Flash      │──►│  NetworkX + SQLite    │
│  • Maps views (accessibility  │   └──────────────────────┘
│    tree snapshots, 200-400tok)│
│  • Logs API traffic           │──►┌──────────────────────┐
└───────────────────────────────┘   │  VectorStore          │
                                    │  ChromaDB (local)     │
┌───────────────────────────────┐   │  all-MiniLM-L6-v2    │
│  Phase 2: MUTATOR             │◄──└──────────────────────┘
│  Model: Llama 4 Scout (Groq)  │
│  • Queries vector store       │  Mutation classes:
│  • LLM + rule-based mutations │  • IDOR (CWE-639)
│  • ~750 tok/s throughput      │  • Price Manipulation
└───────────────────────────────┘  • Privilege Escalation
    │                              • Trust Boundary Violation
    ▼
┌───────────────────────────────┐
│  Phase 3: ATTACK LOOP         │
│  Orchestrator coordinates:    │
│  ① Navigate to target page   │
│  ② Register route intercept  │  ← Playwright route()
│  ③ Inject mutated payload    │  ← page.route() fulfil
│  ④ EVALUATOR verifies result │
│     Model: Gemini 2.5 Flash   │
│     DOM diff + response check │
└───────────────────────────────┘
    │
    ▼
 findings.json  (PoC HTTP chains, severity, CWE IDs)
```

---

## Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Browser automation | `@playwright/mcp@latest` (Node.js) | Structured a11y trees, not pixels |
| Explorer / Evaluator LLM | Google Gemini 2.5 Flash | High context, strong reasoning |
| Mutator LLM | Groq + Llama 4 Scout | 750+ tok/s for rapid payload gen |
| Vector memory | ChromaDB (local) | Semantic payload recall |
| State graph | NetworkX + SQLite | BFS, path-finding, persistence |
| Orchestration | Python asyncio | Async MCP + LLM coordination |

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 20+
- Docker (for test targets)

### 1. Install
```bash
git clone <this-repo>
cd red_team_scanner
chmod +x setup.sh && ./setup.sh
```

### 2. Configure
```bash
cp .env.example .env
# Edit .env — add GEMINI_API_KEY and GROQ_API_KEY
```

### 3. Start an authorised test target
```bash
# OWASP Juice Shop (recommended first target)
docker run -p 3000:3000 bkimminich/juice-shop

# Or WebGoat
docker run -p 8080:8080 webgoat/goat-and-wolf

# Or DVWA
docker run -p 8081:80 vulnerables/web-dvwa
```

### 4. Run
```bash
source venv/bin/activate
python main.py --target http://localhost:3000
```

---

## CLI Reference

```
python main.py [OPTIONS]

Options:
  --target URL      Target application URL (required)
  --explore N       Max Explorer steps (default: 50)
  --attacks N       Max attack hypotheses (default: 25)
  --visible         Run browser in headed mode (debugging)
  --export-graph    Export state graph to reports/state_graph.json
  --log-level LVL   DEBUG | INFO | WARNING | ERROR
  --report PATH     Output JSON report path
```

---

## Output

The scanner produces `reports/findings.json` with:

```json
{
  "tool": "Red Team Logic Scanner (Tri-Agent Swarm)",
  "scan_target": "http://localhost:3000",
  "total_confirmed": 3,
  "severity_counts": { "HIGH": 2, "CRITICAL": 1 },
  "findings": [
    {
      "vuln_type": "IDOR",
      "cwe_id": "CWE-639",
      "severity": "HIGH",
      "confidence": 0.92,
      "endpoint": "**/api/v1/users/*",
      "field_changed": "user_id",
      "original_payload": { "user_id": 5 },
      "malicious_payload": { "user_id": 6 },
      "evidence": "Response contains email: victim@example.com (not attacker's email)",
      "http_chain": [...]
    }
  ]
}
```

Each finding includes the **full HTTP PoC chain** (request + response) for
developer reproduction — equivalent to a Burp Suite export.

---

## Vulnerability Classes

| Class | CWE | Detection Method |
|-------|-----|-----------------|
| IDOR / BAC | CWE-639 | Swap integer/UUID resource IDs |
| Price Manipulation | CWE-840 | Set price/quantity to 0 or negative |
| Privilege Escalation | CWE-269 | Inject `role=admin` or `is_admin=true` |
| Trust Boundary Violation | CWE-501 | Inject server-side-only fields |

---

## Benchmarking

Test against OWASP Benchmark v1.2 to measure True/False positive rates:

```bash
# Clone the benchmark
git clone https://github.com/OWASP/BenchmarkJava
cd BenchmarkJava && mvn package
java -jar target/benchmark.war &   # starts on :8443

# Run scanner
python main.py --target https://localhost:8443/benchmark/ \
               --explore 200 --attacks 100
```

---

## Developer Notes

### Shadow DOM
If the target uses Web Components, the accessibility tree may not see nested
elements. Add `--visible` and inspect manually; implement `internal::shadow`
locators in `mcp_client.py → snapshot()` as needed.

### PII Handling
`config.HASH_PII = True` (default) SHA-256-hashes email, phone, and SSN
patterns in payloads before sending to external LLM APIs (Gemini / Groq).

### Token Budget
- Explorer accessibility snapshots: ~200-400 tokens/page
- Evaluator prompts: ~2,500 tokens/check
- Mutator prompts: ~800 tokens/endpoint
- Estimated total for 50-step scan: ~150k tokens (Gemini) + ~40k (Groq)

### Extending: Add a new mutation class
1. Add detection logic in `memory/vector_store.py → VectorStore`
2. Add a rule in `agents/mutator.py → _rule_based_mutations()`
3. Add a query method in `VectorStore` and call it in `MutatorAgent.generate_hypotheses()`
4. Add a verification heuristic in `agents/evaluator.py → _heuristic_check()`

---

## References

- Escape.tech (2026). *Benchmarking AI Pentesting Tools*
- OWASP Foundation (2025). *OWASP Benchmark v1.2*
- Microsoft. *playwright-mcp* — github.com/microsoft/playwright-mcp
- Anthropic. *MCP Python SDK* — github.com/modelcontextprotocol/python-sdk
