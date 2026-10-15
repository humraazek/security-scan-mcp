# Security Scan MCP

A lightweight, non-destructive Model Context Protocol (MCP) server that provides automated web application security posture assessments for AI agents.

Designed specifically for local AI security setups (such as LibreChat + Ollama + Playwright), this tool allows local language models to inspect security headers, detect common misconfigurations, probe for input reflection, identify database syntax errors, and decode JSON Web Tokens without risk of system destruction.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/humraazek/security-scan-mcp.git
cd security-scan-mcp

# 2. Install dependencies
npm install

# 3. Run the automated test suite
npm test

# 4. Start the MCP server
npm start
```

The server will listen at `http://127.0.0.1:8932/sse`.

---

## 1. Project Overview

`security-scan-mcp` bridges the gap between AI agents and web application security auditing.

When small local LLMs (such as 3B to 8B parameter models) are given dozens of granular security tools, they frequently skip tests, call tools out of order, or hallucinate findings. `security-scan-mcp` solves this by grouping checks into **three high-level, parallelized tools** and computing severities and OWASP mappings server-side.

All checks are strictly **read-only or single benign probe operations**. The tool never brute-forces credentials, extracts database records, or executes arbitrary code on targets.

---

## 2. Features

- **Origin Assessment (`scan_origin`)**: Parallel checks for security headers (HSTS, CSP, X-Frame-Options, COOP), cookie hygiene, sensitive file leaks, CORS policies, dangerous HTTP methods, directory listings, TLS health, and debug error leakage.
- **Security Posture Score**: Automatically grades security headers from **A to F** based on industry standard best practices.
- **Parameter Probing (`scan_parameter`)**: Non-destructive checks for unencoded input reflection (XSS indicators), error-based SQL syntax errors (SQLi indicators), and open redirects.
- **JWT Hygiene Inspection (`decode_jwt`)**: Passive decoding of JWT tokens to flag unsigned tokens (`alg: none`), weak HMAC usage, missing or expired claims, and sensitive cleartext fields.
- **SSRF Defense**: Built-in DNS resolution and IP filtering to prevent scanning internal subnets, loopback interfaces, or cloud metadata endpoints.
- **Single Page Application (SPA) Aware**: Inspects content signatures and MIME types to prevent false-positive alerts on React/Vue/Next.js fallback routes.
- **Memory & Resource Caps**: Enforces request timeouts and a 1 MB response buffer limit to protect against hanging connections or memory exhaustion.

---

## 3. Architecture

```
[ Local AI Agent (LibreChat / Ollama) ]
                 │
                 │ (SSE / Streamable HTTP)
                 ▼
     [ security-scan-mcp Server ]
     ├── SSRF & DNS Resolver Guard
     ├── Bounded LRU Cache (3-minute TTL)
     └── Execution Engine
           ├── scan_origin     ──► Parallel Target Probes
           ├── scan_parameter  ──► Benign Canary Requests
           └── decode_jwt      ──► Passive Token Decoding
```

1. **Client Interface**: Communicates via standard MCP Server-Sent Events (SSE) over HTTP.
2. **Safety Pipeline**: Incoming URLs are validated against protocol restrictions and private IP blocklists before network requests are dispatched.
3. **Execution Layer**: Checks run concurrently using Node.js native `fetch` with strict timeouts.
4. **Structured Output**: Returns normalized JSON responses with distinct `findings` (issues to address), `passed` (clean checks), and `summary` counts.

---

## 4. Prerequisites

- **Node.js**: Version 18.0.0 or later (tested on Node.js v20+ and v24).
- **Package Manager**: `npm` (included with Node.js).
- **MCP Client**: Any MCP-compatible client (e.g., [LibreChat](https://www.librechat.ai/), Claude Desktop, or custom agent runners).

---

## 5. Installation

```bash
# Clone the repository
git clone https://github.com/humraazek/security-scan-mcp.git
cd security-scan-mcp

# Install dependencies
npm install
```

---

## 6. Configuration

Configuration is managed via environment variables. Copy the sample environment file to get started:

```bash
cp .env.example .env
```

### Available Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `HOST` | `127.0.0.1` | Network interface to bind. Use `127.0.0.1` for local usage, or `0.0.0.0` inside Docker containers. |
| `PORT` | `8932` | HTTP port for the MCP SSE transport server. |
| `AUTH_TOKEN` | *(empty)* | Optional Bearer token required for connecting to `/sse` and `/messages`. |
| `ALLOW_PRIVATE_TARGETS` | `false` | When `false`, blocks private RFC 1918 IPs and cloud metadata (`169.254.169.254`). Set to `true` or `1` only to test local containers. |
| `FETCH_TIMEOUT_MS` | `7000` | Timeout per probe request in milliseconds. |
| `MAX_RESPONSE_BYTES` | `1048576` | Maximum response body buffer cap in bytes (1 MB default). |
| `ALLOWED_ORIGINS` | *(empty)* | Comma-separated list of allowed browser origins for cross-origin requests. |

---

## 7. Running the Server

### Development Mode

Run directly with Node.js:

```bash
npm start
```

### Production / Container Mode

If deploying inside Docker or alongside containers:

```bash
HOST=0.0.0.0 PORT=8932 npm start
```

You can verify the server is running by querying the health endpoint:

```bash
curl http://127.0.0.1:8932/health
```

---

## 8. MCP Client Setup

### LibreChat Setup

Add the server definition to your `librechat.yaml` file:

```yaml
mcpServers:
  security-scan:
    type: sse
    url: http://host.docker.internal:8932/sse
    timeout: 120000

mcpSettings:
  allowedDomains:
    - 'host.docker.internal:8932'
    - 'localhost:8932'
```

Restart your LibreChat container to apply the configuration:

```bash
docker compose down
docker compose up -d
```

In the LibreChat Agent Builder:
1. Enable `security-scan` and `playwright`.
2. Paste the contents of `AGENT_INSTRUCTIONS.md` into the Agent's instruction prompt.

---

## 9. Available Tools

### 1. `scan_origin`
Runs a parallel battery of non-destructive checks against a target origin.

- **Arguments**:
  - `url` (*string, required*): Any valid URL on the target origin (e.g., `https://example.com/`). Maximum 2048 characters.
- **Checks Included**:
  - Security headers & posture letter grade (A–F).
  - CSP configuration (flags `'unsafe-inline'` and `'unsafe-eval'`).
  - Cookie security attributes (`Secure`, `HttpOnly`, `SameSite`).
  - Public exposure of sensitive files (`.git/config`, `.env`, backup files).
  - CORS misconfigurations (wildcard with credentials, reflected origins).
  - Dangerous HTTP methods via `OPTIONS` (`PUT`, `DELETE`, `TRACE`).
  - Directory listing / autoindexing.
  - TLS certificate expiry and deprecated protocols (TLS 1.0/1.1).
  - Framework error disclosure on custom 404 paths.
- **Side Effects**: Issues non-destructive HTTP `GET`, `OPTIONS`, and TLS handshakes. Results are cached in memory for 3 minutes.

### 2. `scan_parameter`
Performs benign query parameter analysis.

- **Arguments**:
  - `url` (*string, required*): The target endpoint URL.
  - `paramName` (*string, required*): The observed query parameter name (e.g., `q` or `redirect`). Must be alphanumeric.
- **Checks Included**:
  - Reflected input test using benign canary `mcpProbe1<>"'`. Validates response MIME type to avoid flagging JSON API responses.
  - Database error signature check using a single apostrophe (`test'`).
  - Open redirect validation using external test targets.
- **Side Effects**: Sends benign probe queries with target query parameters.

### 3. `decode_jwt`
Passively inspects JSON Web Tokens without making network requests.

- **Arguments**:
  - `token` (*string, required*): Raw JWT string from a cookie or Authorization header.
- **Checks Included**:
  - Unsigned tokens (`alg: "none"`).
  - Symmetric HMAC algorithm advisory (`HS256`).
  - Missing or expired `exp` claims.
  - Sensitive plaintext key exposure in payload (`password`, `api_key`, `secret`).
- **Side Effects**: None (pure in-memory parsing).

---

## 10. Resources and Prompts

This server does not expose static MCP resources or template prompts. Workflow orchestration is governed by tool invocation as described in [AGENT_INSTRUCTIONS.md](AGENT_INSTRUCTIONS.md).

---

## 11. Security & Trust Boundaries

- **Local Trust Boundary**: By default, the server binds to `127.0.0.1`. Do not expose this server to untrusted public networks without configuring `AUTH_TOKEN`.
- **SSRF Defense**: The server actively resolves DNS hostnames and rejects private RFC 1918 subnets, loopbacks, and link-local metadata addresses (`169.254.169.254`). If testing local containers, explicitly enable `ALLOW_PRIVATE_TARGETS=1`.
- **Audit Limitation**: This tool is an automated, non-destructive surface scanner. It does **not** replace a professional manual penetration test. It does not check for blind SQL injection, complex business logic flaws, or advanced authentication bypasses.
- **Authorization**: Only scan domains and applications you own or have explicit written permission to test.

---

## 12. Testing & Quality Checks

Run the automated test suite using Node.js's built-in test runner:

```bash
# Run security and unit tests
npm test

# Syntax verification
node --check server.js

# Dependency vulnerability check
npm audit
```

---

## 13. Troubleshooting

### Connection Refused (`ECONNREFUSED`)
- Ensure the MCP server is running (`npm start`) in an open terminal.
- When running LibreChat inside Docker, ensure `HOST=0.0.0.0` is set and LibreChat connects via `http://host.docker.internal:8932/sse`.

### SSRF Guard Error: Target is a local/internal address
- The target domain or IP resolves to a private or loopback subnet.
- If you are intentionally scanning a local development server, start the server with:
  ```bash
  ALLOW_PRIVATE_TARGETS=1 npm start
  ```

### Server Hangs on Slow Targets
- Outbound requests default to a 7-second timeout. Adjust this by setting `FETCH_TIMEOUT_MS=10000` if scanning high-latency endpoints.

---

## 14. Project Structure

```
.
├── AGENT_INSTRUCTIONS.md       # System prompt for LLM security analyst agents
├── README.md                   # Project documentation
├── librechat-config-snippet.yaml # Sample configuration for LibreChat integration
├── package.json                # Project dependencies and test scripts
├── server.js                   # MCP server implementation and security check logic
├── test/
│   └── security.test.js        # Automated unit and SSRF security tests
└── .env.example                # Example environment variable configuration
```

---

## 15. Contributing & License

Contributions that improve detection accuracy, reduce false positives, or enhance security controls are welcome. Please open an issue or pull request.

Licensed under the [MIT License](LICENSE).
