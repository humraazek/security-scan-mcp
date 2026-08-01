# Local AI Web Application Security Agent (v2)

Extends the "Local AI QA Engineer" stack (Docker + Ollama + LibreChat +
Playwright MCP) into a **Local AI AppSec Agent**, via one custom MCP server:
`security-scan-mcp`.

> ⚠️ **Only point this at applications you own or are explicitly authorized
> to test.** Every check is read-only or uses a single benign probe value —
> nothing here brute-forces credentials, cracks tokens, or executes code on
> the target — but scanning systems you don't own without permission may
> still be illegal in your jurisdiction.

## What changed in v2

The first version exposed 6 separate tools (one per check). In practice,
small local models (e.g. `qwen2.5:3b`) sometimes forgot to call all 6, or
produced reports where a "missing header" recommendation appeared even
though the header was actually present. v2 fixes this by:

- **Consolidating into 3 tools** instead of 6-plus, each doing much more
  work internally, run in parallel:
  - `scan_origin` — headers, cookies, sensitive paths, CORS, HTTP methods,
    directory listing, TLS/cert health, error-page fingerprinting.
  - `scan_parameter` — reflected-input, SQL error signature, open redirect.
  - `decode_jwt` — passive JWT header/payload analysis (alg:none, missing
    expiry, weak HMAC usage). No cracking or forging.
- **Server-computed severity + OWASP mapping** — the model no longer has
  to reason about severity or map to OWASP itself; each finding already
  carries `severity` and `owasp` fields.
- **Explicit `findings` vs `passed` arrays** — makes it structurally
  obvious which checks failed vs. which passed, so the model can't
  accidentally recommend "fixing" something that already passed.
- **A 3-minute in-memory cache** per origin/parameter, so if the model
  calls the same scan twice it doesn't redo the network requests.

## What it covers

| Tool | Checks (parallelized internally) |
|---|---|
| `scan_origin` | Security headers, cookie flags, sensitive/leaked file paths (`.git`, `.env`, backups), CORS misconfiguration, risky HTTP methods (OPTIONS), directory listing, TLS protocol + certificate expiry, stack-trace/debug-page leakage on error pages |
| `scan_parameter` | Reflected-XSS indicator (encoding check), error-based SQL injection signature, open redirect |
| `decode_jwt` | alg:none detection, symmetric-algorithm flag, missing/expired `exp` claim |

All of this was tested end-to-end against a deliberately-misconfigured
local target before shipping — confirmed each check fires correctly and
none produce false positives on a clean target.

## Setup

### 1. Install and run the MCP server

```bash
cd security-scan-mcp
npm install
node server.js
```

Starts an MCP server on `http://0.0.0.0:8932/sse` (same pattern as the
Playwright MCP server on port 8931). Leave it running in its own terminal
— closing this window stops the server and disconnects it from LibreChat.

### 2. Register it in LibreChat

Merge `librechat-config-snippet.yaml` into your `librechat.yaml`, then do a
full recreate (not just `restart`) so the config is definitely picked up:

```bash
docker compose down
docker compose up -d
```

### 3. Connect it in the UI

**MCP Settings → +** → URL: `http://host.docker.internal:8932/sse`,
Transport: SSE, Authentication: None → check "I trust this application" →
**Create** → **Connect**.

### 4. Build/update the agent

In **Agent Builder**: add both `playwright` and `security-scan` as MCP
tools, and paste the full contents of `AGENT_INSTRUCTIONS.md` into
Instructions (this replaces any earlier version — the tool names changed).

### 5. Run it

```
Go to http://<your-test-target> and scan the origin. Then find the search
box, note its parameter name, and scan that parameter. Give me a report.
```

## A note on "as powerful as possible"

The checks here were deliberately kept to detection, not exploitation —
e.g. a single apostrophe to detect a SQL error signature, not a UNION-based
extraction; a canary string to detect reflection, not a working XSS payload
chain. That's not a limitation of what MCP or this stack can do — it's
what keeps this a security *testing* tool instead of an attack tool, and
it's the same boundary real DAST products (OWASP ZAP, Burp's passive/light
active scanner) operate within. "Powerful" here means broad, accurate
coverage and a report you can actually act on — not deeper exploitation.

## Extending further

- Add a GitHub MCP server so the agent can open an issue per finding.
- Add a `check_response_time_anomaly` tool for basic blind-SQLi timing
  signals (still detection-only — measure delay, don't extract data).
- Swap the fixed `SENSITIVE_PATHS` / `COMMON_DIRS` lists for ones loaded
  from a config file so you can tune them per project.
- Persist scan history (e.g. via a small SQLite file) so the agent can
  report deltas between scans over time.
