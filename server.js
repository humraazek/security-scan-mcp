/**
 * security-scan-mcp
 *
 * A local MCP server exposing NON-DESTRUCTIVE web application security
 * checks, consolidated into a small number of high-coverage tools so a
 * small local LLM can orchestrate them reliably.
 *
 * ONLY run this against applications you own or are explicitly authorized
 * to test. Every check is a read-only request or a single benign probe -
 * nothing here extracts data, brute-forces credentials, cracks tokens, or
 * executes code on the target.
 */

import express from "express";
import tls from "node:tls";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

const PORT = process.env.PORT || 8932;
const CACHE_TTL_MS = 3 * 60 * 1000; // 3 minutes
const cache = new Map();

function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.time > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  return hit.value;
}
function cacheSet(key, value) {
  cache.set(key, { value, time: Date.now() });
}

const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
function sortAndSplit(allFindings) {
  const findings = allFindings.filter((f) => f.severity !== "Info").sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const passed = allFindings.filter((f) => f.severity === "Info");
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.severity === "Critical") summary.critical++;
    else if (f.severity === "High") summary.high++;
    else if (f.severity === "Medium") summary.medium++;
    else if (f.severity === "Low") summary.low++;
  }
  return { findings, passed, summary };
}

// ---------------------------------------------------------------------------
// Individual check implementations (pure functions, no MCP dependency)
// ---------------------------------------------------------------------------

async function checkSecurityHeaders(url) {
  const res = await fetch(url, { redirect: "follow" });
  const headers = res.headers;
  const checks = [
    { name: "Strict-Transport-Security", header: "strict-transport-security", severity: "High", owasp: "A02:2021 Cryptographic Failures", advice: "Add HSTS to enforce HTTPS and prevent downgrade / MITM attacks." },
    { name: "Content-Security-Policy", header: "content-security-policy", severity: "High", owasp: "A05:2021 Security Misconfiguration", advice: "Add a CSP to mitigate XSS and data-injection attacks." },
    { name: "X-Frame-Options", header: "x-frame-options", severity: "Medium", owasp: "A05:2021 Security Misconfiguration", advice: "Add X-Frame-Options (or frame-ancestors in CSP) to prevent clickjacking." },
    { name: "X-Content-Type-Options", header: "x-content-type-options", severity: "Low", owasp: "A05:2021 Security Misconfiguration", advice: "Add 'nosniff' to prevent MIME-sniffing attacks." },
    { name: "Referrer-Policy", header: "referrer-policy", severity: "Low", owasp: "A05:2021 Security Misconfiguration", advice: "Set a Referrer-Policy to limit information leakage in the Referer header." },
    { name: "Permissions-Policy", header: "permissions-policy", severity: "Low", owasp: "A05:2021 Security Misconfiguration", advice: "Restrict powerful browser features via Permissions-Policy." },
  ];
  const findings = [];
  for (const c of checks) {
    if (!headers.get(c.header)) {
      findings.push({ finding: `Missing ${c.name} header`, severity: c.severity, owasp: c.owasp, recommendation: c.advice, location: url });
    } else {
      findings.push({ finding: `${c.name} header present`, severity: "Info", location: url });
    }
  }
  const serverHeader = headers.get("server");
  const poweredBy = headers.get("x-powered-by");
  if (serverHeader) findings.push({ finding: `Server header discloses: "${serverHeader}"`, severity: "Low", owasp: "A05:2021 Security Misconfiguration", recommendation: "Suppress or genericize the Server header to reduce fingerprinting.", location: url });
  if (poweredBy) findings.push({ finding: `X-Powered-By discloses: "${poweredBy}"`, severity: "Low", owasp: "A05:2021 Security Misconfiguration", recommendation: "Remove the X-Powered-By header.", location: url });
  return { status: res.status, findings };
}

async function checkCookies(url) {
  const res = await fetch(url, { redirect: "follow" });
  const cookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
  const findings = [];
  for (const c of cookies) {
    const lower = c.toLowerCase();
    const issues = [];
    if (!lower.includes("secure")) issues.push("missing Secure flag");
    if (!lower.includes("httponly")) issues.push("missing HttpOnly flag");
    if (!lower.includes("samesite")) issues.push("missing SameSite attribute");
    const name = c.split(";")[0];
    if (issues.length) {
      findings.push({ finding: `Cookie '${name}' has issues: ${issues.join(", ")}`, severity: "Medium", owasp: "A07:2021 Identification and Authentication Failures", recommendation: "Set Secure, HttpOnly, and SameSite on all session/auth cookies.", location: url });
    } else {
      findings.push({ finding: `Cookie '${name}' has all recommended flags set`, severity: "Info", location: url });
    }
  }
  return { cookieCount: cookies.length, findings };
}

const SENSITIVE_PATHS = [
  "/.git/config", "/.env", "/.well-known/security.txt", "/robots.txt",
  "/.DS_Store", "/wp-config.php.bak", "/config.php.bak", "/.aws/credentials",
];
async function checkSensitivePaths(origin) {
  const findings = [];
  await Promise.all(
    SENSITIVE_PATHS.map(async (path) => {
      try {
        const res = await fetch(origin + path, { redirect: "manual" });
        if (res.status === 200) {
          const infoOnly = path.includes("robots") || path.includes("security.txt");
          findings.push({
            finding: `${path} is publicly accessible`,
            severity: infoOnly ? "Info" : "High",
            owasp: infoOnly ? undefined : "A01:2021 Broken Access Control",
            recommendation: infoOnly ? undefined : "Remove or restrict access to this path; verify no secrets are exposed.",
            location: origin + path,
          });
        }
      } catch {
        /* unreachable path - skip */
      }
    })
  );
  return { findings };
}

async function checkCors(url) {
  const testOrigin = "https://mcp-cors-probe.example.org";
  const res = await fetch(url, { headers: { Origin: testOrigin } });
  const acao = res.headers.get("access-control-allow-origin");
  const acac = res.headers.get("access-control-allow-credentials");
  const findings = [];
  if (acao === "*" && acac === "true") {
    findings.push({ finding: "CORS allows any origin (*) together with Allow-Credentials: true", severity: "High", owasp: "A05:2021 Security Misconfiguration", recommendation: "Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true.", location: url });
  } else if (acao === testOrigin) {
    findings.push({ finding: "Server reflects an arbitrary Origin header back in Access-Control-Allow-Origin", severity: acac === "true" ? "Critical" : "High", owasp: "A05:2021 Security Misconfiguration", recommendation: "Validate Origin against an explicit allow-list rather than reflecting it.", location: url });
  } else {
    findings.push({ finding: "CORS does not reflect an arbitrary test origin", severity: "Info", location: url });
  }
  return { acao, acac, findings };
}

async function checkHttpMethods(url) {
  const res = await fetch(url, { method: "OPTIONS" }).catch(() => null);
  if (!res) return { findings: [] };
  const allow = res.headers.get("allow") || "";
  const methods = allow.split(",").map((m) => m.trim().toUpperCase()).filter(Boolean);
  const risky = methods.filter((m) => ["PUT", "DELETE", "TRACE", "CONNECT"].includes(m));
  const findings = risky.length
    ? [{ finding: `Potentially risky HTTP methods enabled: ${risky.join(", ")}`, severity: "Medium", owasp: "A05:2021 Security Misconfiguration", recommendation: "Disable HTTP methods not required by the application (PUT/DELETE/TRACE) at the web server or framework level.", location: url }]
    : [{ finding: "No risky HTTP methods (PUT/DELETE/TRACE/CONNECT) observed via OPTIONS", severity: "Info", location: url }];
  return { allow, methods, findings };
}

const COMMON_DIRS = ["/images/", "/uploads/", "/backup/", "/assets/", "/files/", "/static/"];
async function checkDirectoryListing(origin) {
  const findings = [];
  await Promise.all(
    COMMON_DIRS.map(async (dir) => {
      try {
        const res = await fetch(origin + dir, { redirect: "manual" });
        if (res.status === 200) {
          const body = await res.text();
          if (/Index of \//i.test(body) || /<title>Directory Listing/i.test(body)) {
            findings.push({ finding: `Directory listing enabled at ${dir}`, severity: "Medium", owasp: "A05:2021 Security Misconfiguration", recommendation: "Disable directory listing / autoindex on the web server.", location: origin + dir });
          }
        }
      } catch {
        /* skip unreachable dir */
      }
    })
  );
  return { findings };
}

async function checkErrorFingerprint(origin) {
  const probePath = "/mcp-nonexistent-probe-" + Math.random().toString(36).slice(2);
  const res = await fetch(origin + probePath).catch(() => null);
  if (!res) return { findings: [] };
  const body = await res.text();
  const signatures = [/at\s+[\w.$]+\s+\(.*:\d+:\d+\)/, /Traceback \(most recent call last\)/i, /Fatal error:/i, /Whitelabel Error Page/i, /System\.Exception/i, /Stack trace:/i];
  const matched = signatures.some((re) => re.test(body));
  const findings = matched
    ? [{ finding: "Error/404 page appears to leak a stack trace or framework debug page", severity: "Medium", owasp: "A05:2021 Security Misconfiguration", recommendation: "Disable debug mode and use generic error pages in production.", location: origin + probePath }]
    : [{ finding: "404/error page does not appear to leak stack traces", severity: "Info", location: origin }];
  return { status: res.status, findings };
}

function checkTls(hostname, port = 443) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 5000 }, () => {
      if (settled) return;
      settled = true;
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const findings = [];
      if (protocol === "TLSv1" || protocol === "TLSv1.1") {
        findings.push({ finding: `Weak TLS protocol in use: ${protocol}`, severity: "High", owasp: "A02:2021 Cryptographic Failures", recommendation: "Disable TLS 1.0/1.1; require TLS 1.2+ (ideally 1.3).", location: hostname });
      } else if (protocol) {
        findings.push({ finding: `TLS protocol in use: ${protocol}`, severity: "Info", location: hostname });
      }
      let daysToExpiry = null;
      if (cert && cert.valid_to) {
        daysToExpiry = Math.round((new Date(cert.valid_to) - Date.now()) / 86400000);
        if (daysToExpiry < 0) findings.push({ finding: "TLS certificate has already expired", severity: "Critical", owasp: "A02:2021 Cryptographic Failures", recommendation: "Renew the TLS certificate immediately.", location: hostname });
        else if (daysToExpiry < 30) findings.push({ finding: `TLS certificate expires in ${daysToExpiry} day(s)`, severity: "Medium", owasp: "A02:2021 Cryptographic Failures", recommendation: "Renew the TLS certificate before it expires.", location: hostname });
        else findings.push({ finding: `TLS certificate valid for ${daysToExpiry} more day(s)`, severity: "Info", location: hostname });
      }
      socket.end();
      resolve({ protocol, cipher: socket.getCipher()?.name, validTo: cert?.valid_to, daysToExpiry, findings });
    });
    socket.on("error", (err) => {
      if (settled) return;
      settled = true;
      resolve({ error: err.message, findings: [] });
    });
    socket.setTimeout(5000, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ error: "TLS connection timed out", findings: [] });
    });
  });
}

async function checkReflectedInput(url, paramName) {
  const canary = `mcpProbe1<>"'`;
  const target = new URL(url);
  target.searchParams.set(paramName, canary);
  const res = await fetch(target.toString());
  const body = await res.text();
  const reflectedRaw = body.includes(canary);
  const reflectedEscaped = body.includes("mcpProbe1&lt;&gt;&quot;&#39;") || body.includes("mcpProbe1&lt;&gt;&#34;&#39;");
  let finding;
  if (reflectedRaw) finding = { finding: `Parameter '${paramName}' is reflected without HTML-encoding`, severity: "High", owasp: "A03:2021 Injection", recommendation: "Contextually output-encode all user-controlled data before rendering it in HTML.", location: target.toString() };
  else if (reflectedEscaped) finding = { finding: `Parameter '${paramName}' is reflected but appears HTML-encoded`, severity: "Info", location: target.toString() };
  else finding = { finding: `Parameter '${paramName}' was not reflected in the response`, severity: "Info", location: target.toString() };
  return { findings: [finding] };
}

const SQL_ERROR_SIGNATURES = [
  /you have an error in your sql syntax/i, /warning: mysql/i, /unclosed quotation mark/i,
  /ORA-\d{5}/, /PostgreSQL.*ERROR/i, /SQLite3?::/i, /Microsoft OLE DB Provider for SQL Server/i, /pg_query\(\)/i,
];
async function checkSqlErrorSignatures(url, paramName) {
  const target = new URL(url);
  target.searchParams.set(paramName, `test'`);
  const res = await fetch(target.toString());
  const body = await res.text();
  const matched = SQL_ERROR_SIGNATURES.filter((re) => re.test(body));
  const finding = matched.length
    ? { finding: `Parameter '${paramName}' triggered a database error signature`, severity: "Critical", owasp: "A03:2021 Injection", recommendation: "Use parameterized queries / prepared statements. Never build SQL from raw user input.", evidence: matched.map(String), location: target.toString() }
    : { finding: `No database error signatures observed for parameter '${paramName}'`, severity: "Info", location: target.toString() };
  return { findings: [finding] };
}

async function checkOpenRedirect(url, paramName) {
  const probe = "https://example.org/mcp-redirect-probe";
  const target = new URL(url);
  target.searchParams.set(paramName, probe);
  const res = await fetch(target.toString(), { redirect: "manual" });
  const location = res.headers.get("location");
  const vulnerable = res.status >= 300 && res.status < 400 && location && location.startsWith(probe);
  const finding = vulnerable
    ? { finding: `Parameter '${paramName}' causes an unvalidated redirect to attacker-controlled URLs`, severity: "Medium", owasp: "A01:2021 Broken Access Control", recommendation: "Validate redirect targets against an allow-list of internal paths/domains.", location: target.toString() }
    : { finding: `No open redirect observed for parameter '${paramName}'`, severity: "Info", location: target.toString() };
  return { findings: [finding] };
}

// ---------------------------------------------------------------------------
// MCP server factory - a fresh instance is created per SSE connection
// ---------------------------------------------------------------------------
function createMcpServer() {
  const server = new McpServer({ name: "security-scan-mcp", version: "2.0.0" });

  server.tool(
    "scan_origin",
    "Runs a full battery of non-destructive origin-level security checks IN PARALLEL: security headers, cookie flags, sensitive/leaked file paths, CORS misconfiguration, risky HTTP methods, directory listing, TLS/certificate health, and error-page fingerprinting. Returns ONE consolidated, severity-sorted report with OWASP Top 10 mapping already computed. Call this exactly ONCE per distinct origin - do not call individual checks separately.",
    { url: z.string().url().describe("Any URL on the target origin, e.g. https://example.com/ or https://example.com/page") },
    async ({ url }) => {
      const origin = new URL(url).origin;
      const hostname = new URL(url).hostname;
      const isHttps = new URL(url).protocol === "https:";
      const cacheKey = `origin:${origin}`;
      const cached = cacheGet(cacheKey);
      if (cached) return { content: [{ type: "text", text: JSON.stringify({ ...cached, cached: true }, null, 2) }] };

      const [headers, cookies, sensitive, cors, methods, dirs, errFp, tls_] = await Promise.all([
        checkSecurityHeaders(url).catch((e) => ({ findings: [], error: e.message })),
        checkCookies(url).catch((e) => ({ findings: [], error: e.message })),
        checkSensitivePaths(origin).catch((e) => ({ findings: [], error: e.message })),
        checkCors(url).catch((e) => ({ findings: [], error: e.message })),
        checkHttpMethods(url).catch((e) => ({ findings: [], error: e.message })),
        checkDirectoryListing(origin).catch((e) => ({ findings: [], error: e.message })),
        checkErrorFingerprint(origin).catch((e) => ({ findings: [], error: e.message })),
        isHttps ? checkTls(hostname).catch((e) => ({ findings: [], error: e.message })) : Promise.resolve({ skipped: "target is not HTTPS", findings: [] }),
      ]);

      const all = [...headers.findings, ...cookies.findings, ...sensitive.findings, ...cors.findings, ...methods.findings, ...dirs.findings, ...errFp.findings, ...tls_.findings];
      const { findings, passed, summary } = sortAndSplit(all);
      const result = { origin, scannedAt: new Date().toISOString(), checksRun: ["security_headers", "cookies", "sensitive_paths", "cors", "http_methods", "directory_listing", "error_fingerprint", isHttps ? "tls" : "tls_skipped_not_https"], summary, findings, passed };
      cacheSet(cacheKey, result);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "scan_parameter",
    "Runs all non-destructive parameter-level probes IN PARALLEL for a single query parameter: reflected-input (XSS indicator), SQL error-signature (injection indicator), and open-redirect. Returns ONE consolidated report with OWASP mapping. Call this once per parameter discovered on the page - do not call individual checks separately.",
    { url: z.string().url(), paramName: z.string().describe("Query parameter name actually observed on the page, e.g. 'q' or 'redirect'. Never invent a name that wasn't observed.") },
    async ({ url, paramName }) => {
      const cacheKey = `param:${url}:${paramName}`;
      const cached = cacheGet(cacheKey);
      if (cached) return { content: [{ type: "text", text: JSON.stringify({ ...cached, cached: true }, null, 2) }] };

      const [reflected, sqli, redirect] = await Promise.all([
        checkReflectedInput(url, paramName).catch((e) => ({ findings: [], error: e.message })),
        checkSqlErrorSignatures(url, paramName).catch((e) => ({ findings: [], error: e.message })),
        checkOpenRedirect(url, paramName).catch((e) => ({ findings: [], error: e.message })),
      ]);
      const all = [...reflected.findings, ...sqli.findings, ...redirect.findings];
      const { findings, passed, summary } = sortAndSplit(all);
      const result = { url, paramName, checksRun: ["reflected_input", "sql_error_signatures", "open_redirect"], summary, findings, passed };
      cacheSet(cacheKey, result);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "decode_jwt",
    "Decodes a JWT's header and payload (base64) and flags common weaknesses: alg:none, weak/symmetric algorithm usage, missing or expired 'exp' claim. Passive decoding only - does not verify the signature or attempt to crack/forge it.",
    { token: z.string().describe("The raw JWT string, e.g. copied from a cookie or Authorization header") },
    async ({ token }) => {
      const parts = token.split(".");
      if (parts.length < 2) {
        return { content: [{ type: "text", text: JSON.stringify({ error: "Not a valid JWT (expected at least 2 dot-separated segments)" }) }] };
      }
      const decode = (seg) => {
        try {
          return JSON.parse(Buffer.from(seg.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
        } catch {
          return null;
        }
      };
      const header = decode(parts[0]);
      const payload = decode(parts[1]);
      const findings = [];
      if (header?.alg && /none/i.test(header.alg)) {
        findings.push({ finding: `JWT uses alg: "${header.alg}" - signature-less tokens should never be accepted`, severity: "Critical", owasp: "A02:2021 Cryptographic Failures", recommendation: "Reject tokens with alg: none server-side; explicitly allow-list accepted algorithms." });
      } else if (header?.alg && /^HS/i.test(header.alg)) {
        findings.push({ finding: `JWT uses symmetric algorithm ${header.alg}`, severity: "Low", owasp: "A02:2021 Cryptographic Failures", recommendation: "Ensure the HMAC secret is long/random, or prefer asymmetric algorithms (RS256/ES256) for multi-service setups." });
      } else if (header?.alg) {
        findings.push({ finding: `JWT uses algorithm ${header.alg}`, severity: "Info" });
      }
      if (payload && !payload.exp) {
        findings.push({ finding: "JWT payload has no 'exp' (expiration) claim", severity: "Medium", owasp: "A07:2021 Identification and Authentication Failures", recommendation: "Always set a reasonable expiration on issued tokens." });
      } else if (payload?.exp) {
        const expDate = new Date(payload.exp * 1000);
        if (expDate < new Date()) findings.push({ finding: "JWT is expired but was observed/available", severity: "Low", owasp: "A07:2021 Identification and Authentication Failures", recommendation: "Confirm the server actually rejects expired tokens." });
        else findings.push({ finding: `JWT expires ${expDate.toISOString()}`, severity: "Info" });
      }
      return { content: [{ type: "text", text: JSON.stringify({ header, payload, findings }, null, 2) }] };
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// SSE transport wiring
// ---------------------------------------------------------------------------
const app = express();
const transports = {};

app.get("/sse", async (req, res) => {
  const server = createMcpServer();
  const transport = new SSEServerTransport("/messages", res);
  transports[transport.sessionId] = transport;
  res.on("close", () => delete transports[transport.sessionId]);
  await server.connect(transport);
});

app.post("/messages", async (req, res) => {
  const sessionId = req.query.sessionId;
  const transport = transports[sessionId];
  if (transport) {
    await transport.handlePostMessage(req, res);
  } else {
    res.status(400).send("No transport found for sessionId");
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`security-scan-mcp v2 listening on http://0.0.0.0:${PORT}/sse`);
  console.log("Tools: scan_origin, scan_parameter, decode_jwt");
  console.log("Only point this at applications you own or are authorized to test.");
});
