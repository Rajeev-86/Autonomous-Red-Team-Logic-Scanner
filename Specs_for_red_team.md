# Architectural Blueprint: Autonomous "Red Team" Logic Scanner

## 1. Project Overview & Architecture

### The Goal
To build an autonomous swarm of AI agents capable of identifying complex business-logic vulnerabilities (e.g., Broken Access Control, multi-step exploitation, state manipulation) that traditional static scanners and basic DAST tools miss.

### The 2026 Core Concept: The Tri-Agent Swarm
Instead of a single monolithic prompt, the system relies on three specialized agents working in a stateful orchestration loop, interacting with the target via the Model Context Protocol (MCP) using Playwright.

* **The Explorer (Planner):** Maps the application via accessibility trees, logs valid API traffic, and builds a state graph.
* **The Mutator (Generator):** Analyzes intercepted API payloads against the state graph and hypothesizes malicious mutations (e.g., changing IDs, modifying cart totals).
* **The Evaluator (Observer):** Monitors the DOM and network responses after an attack payload is sent to determine if the exploit was successful, verifying the vulnerability.

### The Tech Stack (Open-Source / Free Tier 2026)
* **Execution Layer (Browser Automation):** Playwright + `microsoft/playwright-mcp` (The industry standard as of 2026, running via Node.js).
* **LLM Intelligence Layer:**
    * *Explorer/Evaluator:* Google Gemini 3.5 Flash (via free API tier for high-context DOM analysis).
    * *Mutator:* Groq free tier running Llama 4 Scout or Qwen3 32B (for rapid, high-speed payload generation).
* **Semantic Memory:** Chroma DB (Local Vector Database) or Qdrant (Free Cloud Tier).
* **State Graph:** NetworkX (Python library) paired with SQLite for edge/node mapping.
* **Orchestration Language:** Python (using frameworks like LangChain or AutoGen for swarm coordination) communicating with the Node.js Playwright MCP server.

---

## 2. Module Implementation Details

### Module 1: The MCP Execution Bridge (Node.js)
The foundation of the project is connecting your LLMs to a real browser. In 2026, `microsoft/playwright-mcp` is the default standard because it provides the AI with structured accessibility snapshots rather than pixel-heavy screenshots, which is faster and vastly more token-efficient (costing ~200-400 tokens per snapshot).

* **Implementation Steps:**
    1. Install the official server globally: `npx @playwright/mcp@latest`
    2. Run the server in standard HTTP mode or stdio mode so your Python orchestrator can communicate with it.
    3. **Crucial Configuration:** Ensure the server is configured to expose network interception tools, allowing the AI to use `page.route()` to capture and mock API traffic.
* **How it Works:** The LLM issues a command (e.g., `browser_click(ref="e5")`) via standard JSON over MCP. Playwright executes the action and returns the new accessibility tree state.

### Module 2: The Memory Architecture (Python)
This is where the agent gains stateful awareness, solving the primary challenge of business logic testing.

* **The State Graph (NetworkX):**
    * Every time the Explorer agent lands on a new view, generate a node.
    * *Node Data:* Current URL, concise DOM summary, active Session State.
    * *Edge Data:* The action taken to get there (e.g., `click(ref='btn-checkout')`).
* **The Vector Database (Chroma/Qdrant):**
    * Embed the raw intercepted API payloads (Headers, JSON Body) and the corresponding accessibility tree snapshot.
    * *Why?* When the Mutator agent wants to test an exploit on a new page, it queries the vector DB: *"Find me all past API payloads involving user IDs or financial values."* This allows the agent to generalize attacks across different parts of the application.

### Module 3: The Attack Loop (The Swarm in Action)
This is the core execution loop managed by your Python orchestrator.

1. **Passive Mapping (Explorer):** The Explorer agent uses MCP tools to navigate the target app. It logs every action in the State Graph and embeds every intercepted network request in the Vector DB. It establishes the "happy path."
2. **Hypothesis Generation (Mutator):** The Mutator agent queries the Vector DB for endpoints that look vulnerable to logic flaws (e.g., `/api/v1/update_profile`). It generates a payload, for example, swapping `{"user_id": 1}` to `{"user_id": 2}`.
3. **Active Interception (Execution):** The orchestrator instructs the Playwright MCP server to actively intercept the target API route.
4. **Payload Injection:** The browser attempts the normal UI action. The MCP server catches the request, swaps the legitimate payload with the Mutator's malicious payload, and lets it hit the backend.
5. **Verification (Evaluator):** The Evaluator agent reads the subsequent DOM update and network response via MCP. If the UI successfully loaded User 2's profile data, the agent logs a confirmed Broken Access Control vulnerability.

---

## 3. Evaluation & Benchmarking

To prove the tool works in 2026, you cannot rely on simple True/False positive counts from static scanners. You must evaluate the agent's ability to navigate logic.

* **Primary Metrics:**
    * **Verified Exploitability (PoC Generation):** The tool is only successful if it can output the exact HTTP request/response chain that proves the exploit.
    * **Time to Exploit (TTE):** Measure the time from initial URL provision to successful payload execution.
* **Standardized Test Targets:**
    * **OWASP Benchmark (v1.2):** Released in late 2025, this remains the industry standard for measuring accurate True/False positive rates for specific CWEs.
    * **Duck Store / OWASP Juice Shop:** Use these intentionally vulnerable modern applications (React/FastAPI) to test complex logic flaws, specifically targeting:
        * CWE-501 (Trust Boundary Violation)
        * CWE-22 (Insecure Direct Object Reference)
        * CWE-79 (XSS via Logic Manipulation)

---

## 4. Developer Warnings & Security Guardrails

* **Shadow DOM Constraints:** If your target app heavily uses Web Components (Shadow DOM), the standard accessibility tree snapshots may fail to see nested elements. Your team may need to implement hybrid vision fallback strategies or specialized locators (`internal::shadow`) to penetrate these layers.
* **The PII Boundary:** When agents interact with live data or complex apps, ensure you implement local hashing for any Personally Identifiable Information (PII) *before* sending payloads to external LLM APIs (like Gemini or Groq).
* **Token Optimization:** Because the swarm is chatty, strictly monitor token usage. The Explorer agent should use standard Playwright CLI commands for repetitive setup tasks and only switch to the more token-heavy MCP accessibility trees for deep exploratory reasoning.

---
**Effective Date of Information:** June 2026

**Reference Sources:**
* Escape.tech (April 30, 2026). *Benchmarking AI Pentesting Tools: A Practical Comparison*.
* OWASP Foundation (November 11, 2025). *OWASP Benchmark*.
* Emergent Mind (July 27, 2025). *OWASP Benchmark Project 1.2*.
* Strobes (2026). *AI Pentesting*.