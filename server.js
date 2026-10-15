/**
 * security-scan-mcp v2.2.0
 *
 * Hardened, non-destructive local Model Context Protocol (MCP) server
 * for automated web application security posture assessment.
 *
 * Designed for orchestration with local AI agents (LibreChat, Ollama, Playwright).
 *
 * All operations are strictly read-only or benign probe tests.
 * Never performs destructive actions, data extraction, or brute-force attacks.
 */

import express from "express";
import tls from "node:tls";
import net from "node:net";
import dns from "node:dns/promises";
import url from "node:url";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

// ---------------------------------------------------------------------------
// Configuration & Environment Variables
// ---------------------------------------------------------------------------
export const PORT = parseInt(process.env.PORT || "8932", 10);
export const HOST = process.env.HOST || "127.0.0.1";
export const AUTH_TOKEN = process.env.AUTH_TOKEN || "";
export const ALLOW_PRIVATE_TARGETS =
  process.env.ALLOW_PRIVATE_TARGETS === "true" ||
  process.env.ALLOW_PRIVATE_TARGETS === "1";
export const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "7000", 10);
export const MAX_RESPONSE_BYTES = parseInt(
  process.env.MAX_RESPONSE_BYTES || String(1024 * 1024), // 1 MB cap
  10
);
export const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

export const MAX_CACHE_ENTRIES = 500;
export const CACHE_TTL_MS = 3 * 60 * 1000; // 3 minutes

export const USER_AGENT =
  "SecurityScanMCP/2.2 (Non-destructive AppSec Scanner; +https://github.com/humraazek/security-scan-mcp)";

// ---------------------------------------------------------------------------
// Bounded LRU In-Memory Cache
// ---------------------------------------------------------------------------
export const cache = new Map();

export function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.time > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  // Refresh access position for LRU
  cache.delete(key);
  cache.set(key, hit);
  return hit.value;
}

export function cacheSet(key, value) {
  if (cache.size >= MAX_CACHE_ENTRIES) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey) cache.delete(oldestKey);
  }
  cache.set(key, { value, time: Date.now() });
}

export function cacheClear() {
  cache.clear();
}

// ---------------------------------------------------------------------------
// SSRF & Network Validation
// ---------------------------------------------------------------------------

export function isPrivateOrReservedIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split(".").map(Number);
    const [b0, b1] = parts;
    if (b0 === 127) return true; // Loopback (127.0.0.0/8)
    if (b0 === 10) return true; // RFC 1918 (10.0.0.0/8)
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return true; // RFC 1918 (172.16.0.0/12)
    if (b0 === 192 && b1 === 168) return true; // RFC 1918 (192.168.0.0/16)
    if (b0 === 169 && b1 === 254) return true; // Link-local / Cloud Metadata (169.254.0.0/16)
    if (b0 === 0) return true; // Broadcast / default (0.0.0.0/8)
    if (b0 === 100 && b1 >= 64 && b1 <= 127) return true; // Shared Address Space (100.64.0.0/10)
    if (b0 === 198 && (b1 === 18 || b1 === 19)) return true; // Benchmark testing (198.18.0.0/15)
  } else if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::") return true;
    if (lower.startsWith("fe80:") || lower.startsWith("fc00:") || lower.startsWith("fd")) return true;
  }
  return false;
}

export async function validateAndResolveHost(hostname) {
  const lower = hostname.toLowerCase();

  // Known local/special hostnames
  if (
    lower === "localhost" ||
    lower === "host.docker.internal" ||
    lower.endsWith(".local") ||
    lower.endsWith(".internal")
  ) {
    if (!ALLOW_PRIVATE_TARGETS) {
      throw new Error(
        `SSRF Guard: Target host '${hostname}' is a local/internal name. Set ALLOW_PRIVATE_TARGETS=1 to test local environments.`
      );
    }
    return "127.0.0.1";
  }

  // If already an IP address
  if (net.isIP(lower)) {
    if (!ALLOW_PRIVATE_TARGETS && isPrivateOrReservedIp(lower)) {
      throw new Error(
        `SSRF Guard: IP '${lower}' is in a private or reserved range. Set ALLOW_PRIVATE_TARGETS=1 to test private networks.`
      );
    }
    return lower;
  }

  // Resolve DNS to prevent DNS rebinding attacks
  try {
    const lookup = await dns.lookup(lower);
    if (!ALLOW_PRIVATE_TARGETS && isPrivateOrReservedIp(lookup.address)) {
      throw new Error(
        `SSRF Guard: Domain '${hostname}' resolved to private address '${lookup.address}'. Set ALLOW_PRIVATE_TARGETS=1 to allow.`
      );
    }
    return lookup.address;
  } catch (err) {
    if (err.message.startsWith("SSRF Guard:")) throw err;
    throw new Error(`DNS resolution failed for host '${hostname}': ${err.message}`);
  }
}

/**
 * Safe stream reader with max byte cap to prevent memory exhaustion / DoS
 */
export async function readBodyWithLimit(response, maxBytes = MAX_RESPONSE_BYTES) {
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        totalBytes += value.length;
        chunks.push(value);
        if (totalBytes >= maxBytes) {
          // Reached limit: cancel remaining stream and return truncated content
          await reader.cancel();
          break;
        }
      }
    }
  } catch (err) {
    // If stream aborted or cancelled, continue with collected chunks
  }

  const combined = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }

  return new TextDecoder("utf-8", { fatal: false }).decode(combined);
}

/**
 * Safe fetch wrapper that handles SSRF checks, redirect validation, and timeouts
 */
export async function safeFetch(targetUrl, options = {}, timeoutMs = FETCH_TIMEOUT_MS, maxRedirects = 5) {
  let currentUrl = targetUrl;
  let redirectsRemaining = maxRedirects;

  while (true) {
    const parsed = new URL(currentUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error(`Unsupported protocol '${parsed.protocol}'. Only HTTP and HTTPS are permitted.`);
    }

    // SSRF validation on target host
    await validateAndResolveHost(parsed.hostname);

    const headers = {
      "User-Agent": USER_AGENT,
      Accept: "*/*",
      ...(options.headers || {}),
    };

    const res = await fetch(currentUrl, {
      ...options,
      headers,
      redirect: "manual", // Intercept redirects to validate target host
      signal: AbortSignal.timeout(timeoutMs),
    });

    // Check if redirect should be followed
    const isRedirect = res.status >= 300 && res.status < 400 && res.headers.get("location");
    if (isRedirect && options.redirect !== "manual" && redirectsRemaining > 0) {
      redirectsRemaining--;
      const location = res.headers.get("location");
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    return res;
  }
}

// ---------------------------------------------------------------------------
// Severity Sorting & Summary Helper
// ---------------------------------------------------------------------------
const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

export function sortAndSplit(allFindings) {
  const findings = allFindings
    .filter((f) => f.severity !== "Info")
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
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
// Security Check Implementations
// ---------------------------------------------------------------------------

/**
 * Evaluates HTTP security headers and computes an industry-standard security posture grade
 */
export async function checkSecurityHeaders(url) {
  const res = await safeFetch(url, { redirect: "follow" });
  const headers = res.headers;
  const findings = [];
  let score = 100;

  const headerChecks = [
    {
      name: "Strict-Transport-Security (HSTS)",
      header: "strict-transport-security",
      severity: "High",
      points: 20,
      owasp: "A02:2021 Cryptographic Failures",
      advice: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce encrypted HTTPS.",
    },
    {
      name: "Content-Security-Policy (CSP)",
      header: "content-security-policy",
      severity: "High",
      points: 25,
      owasp: "A05:2021 Security Misconfiguration",
      advice: "Define an explicit Content-Security-Policy to mitigate Cross-Site Scripting (XSS) and code injection.",
    },
    {
      name: "X-Frame-Options",
      header: "x-frame-options",
      severity: "Medium",
      points: 15,
      owasp: "A05:2021 Security Misconfiguration",
      advice: "Configure 'X-Frame-Options: DENY' (or 'frame-ancestors' in CSP) to prevent clickjacking.",
    },
    {
      name: "X-Content-Type-Options",
      header: "x-content-type-options",
      severity: "Low",
      points: 15,
      owasp: "A05:2021 Security Misconfiguration",
      advice: "Set 'X-Content-Type-Options: nosniff' to disable browser MIME-sniffing.",
    },
    {
      name: "Referrer-Policy",
      header: "referrer-policy",
      severity: "Low",
      points: 10,
      owasp: "A05:2021 Security Misconfiguration",
      advice: "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
    },
    {
      name: "Permissions-Policy",
      header: "permissions-policy",
      severity: "Low",
      points: 10,
      owasp: "A05:2021 Security Misconfiguration",
      advice: "Define Permissions-Policy to restrict browser features (camera, microphone, geolocation).",
    },
    {
      name: "Cross-Origin-Opener-Policy (COOP)",
      header: "cross-origin-opener-policy",
      severity: "Low",
      points: 5,
      owasp: "A05:2021 Security Misconfiguration",
      advice: "Set 'Cross-Origin-Opener-Policy: same-origin' to isolate browsing contexts from cross-origin attacks.",
    },
  ];

  for (const c of headerChecks) {
    const val = headers.get(c.header);
    if (!val) {
      score -= c.points;
      findings.push({
        finding: `Missing ${c.name} header`,
        severity: c.severity,
        owasp: c.owasp,
        recommendation: c.advice,
        location: url,
      });
    } else {
      findings.push({
        finding: `${c.name} header configured`,
        severity: "Info",
        evidence: val.slice(0, 100),
        location: url,
      });
    }
  }

  // Deep CSP audit
  const csp = headers.get("content-security-policy");
  if (csp) {
    if (csp.includes("'unsafe-inline'") && !csp.includes("'nonce-") && !csp.includes("'sha256-")) {
      score -= 10;
      findings.push({
        finding: "CSP contains 'unsafe-inline' without nonces or hashes",
        severity: "Medium",
        owasp: "A05:2021 Security Misconfiguration",
        recommendation: "Replace 'unsafe-inline' with cryptographic nonces or hashes to prevent script injection.",
        location: url,
      });
    }
    if (csp.includes("'unsafe-eval'")) {
      score -= 5;
      findings.push({
        finding: "CSP contains 'unsafe-eval'",
        severity: "Low",
        owasp: "A05:2021 Security Misconfiguration",
        recommendation: "Avoid 'unsafe-eval' to prevent dynamic string evaluation via eval() or Function().",
        location: url,
      });
    }
  }

  // Information disclosure headers
  const serverHeader = headers.get("server");
  const poweredBy = headers.get("x-powered-by");
  if (serverHeader) {
    findings.push({
      finding: `Server header discloses banner: "${serverHeader}"`,
      severity: "Low",
      owasp: "A05:2021 Security Misconfiguration",
      recommendation: "Mask or remove the Server header to prevent platform fingerprinting.",
      location: url,
    });
  }
  if (poweredBy) {
    findings.push({
      finding: `X-Powered-By discloses runtime framework: "${poweredBy}"`,
      severity: "Low",
      owasp: "A05:2021 Security Misconfiguration",
      recommendation: "Disable the X-Powered-By response header.",
      location: url,
    });
  }

  score = Math.max(0, score);
  let grade = "F";
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 45) grade = "D";

  return { status: res.status, score, grade, findings };
}

/**
 * Validates cookie flags and security attributes
 */
export async function checkCookies(url) {
  const res = await safeFetch(url, { redirect: "follow" });
  const cookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
  const findings = [];

  for (const c of cookies) {
    const lower = c.toLowerCase();
    const issues = [];
    if (!lower.includes("secure")) issues.push("missing Secure flag");
    if (!lower.includes("httponly")) issues.push("missing HttpOnly flag");
    if (!lower.includes("samesite")) {
      issues.push("missing SameSite attribute");
    } else if (lower.includes("samesite=none") && !lower.includes("secure")) {
      issues.push("SameSite=None configured without Secure flag (rejected by modern browsers)");
    }

    const name = c.split(";")[0];
    if (issues.length) {
      findings.push({
        finding: `Cookie '${name}' security issues: ${issues.join("; ")}`,
        severity: "Medium",
        owasp: "A07:2021 Identification and Authentication Failures",
        recommendation: "Configure 'Secure; HttpOnly; SameSite=Lax' (or Strict) on all session and authentication cookies.",
        location: url,
      });
    } else {
      findings.push({
        finding: `Cookie '${name}' has recommended security attributes`,
        severity: "Info",
        location: url,
      });
    }
  }
  return { cookieCount: cookies.length, findings };
}

export const SENSITIVE_PATHS = [
  { path: "/.git/config", signature: /\[core\]|repositoryformatversion/i, name: "Git repository configuration" },
  { path: "/.env", signature: /^[\w_]+=[^\r\n]*/m, name: "Environment secrets file" },
  { path: "/.aws/credentials", signature: /\[default\]|aws_access_key_id/i, name: "AWS credentials configuration" },
  { path: "/wp-config.php.bak", signature: /DB_PASSWORD|DB_USER/i, name: "WordPress configuration backup" },
  { path: "/config.php.bak", signature: /<\?php|\$config/i, name: "PHP configuration backup" },
  { path: "/.DS_Store", binary: true, name: "macOS metadata archive" },
  { path: "/robots.txt", infoOnly: true, name: "Robots crawler policy" },
  { path: "/.well-known/security.txt", infoOnly: true, name: "Security policy contact" },
];

/**
 * Checks for sensitive/leaked files with SPA false-positive filtering
 */
export async function checkSensitivePaths(origin) {
  const findings = [];
  await Promise.all(
    SENSITIVE_PATHS.map(async (item) => {
      try {
        const res = await safeFetch(origin + item.path, { redirect: "manual" });
        if (res.status === 200) {
          const contentType = (res.headers.get("content-type") || "").toLowerCase();
          const isHtml = contentType.includes("text/html");

          // SPA False-Positive Filter:
          // Single-page apps frequently return 200 with index.html for all routes.
          if (!item.infoOnly && isHtml) {
            const bodyPreview = await readBodyWithLimit(res, 4096);
            if (
              bodyPreview.includes("<!DOCTYPE html") ||
              bodyPreview.includes("<html") ||
              bodyPreview.includes("<title>")
            ) {
              return; // Ignored as SPA fallback
            }
          }

          if (item.signature) {
            const body = await readBodyWithLimit(res, 16384);
            if (!item.signature.test(body)) {
              return; // Content did not match expected structure
            }
          }

          findings.push({
            finding: `${item.name} (${item.path}) is publicly accessible`,
            severity: item.infoOnly ? "Info" : "High",
            owasp: item.infoOnly ? undefined : "A01:2021 Broken Access Control",
            recommendation: item.infoOnly
              ? undefined
              : `Block public access to '${item.path}' in your web server / reverse proxy rules immediately.`,
            location: origin + item.path,
          });
        }
      } catch {
        /* unreachable / timed out - ignored */
      }
    })
  );
  return { findings };
}

/**
 * Evaluates Cross-Origin Resource Sharing (CORS) configurations
 */
export async function checkCors(url) {
  const testOrigin = "https://mcp-cors-probe.example.org";
  const res = await safeFetch(url, { headers: { Origin: testOrigin } });
  const acao = res.headers.get("access-control-allow-origin");
  const acac = res.headers.get("access-control-allow-credentials");
  const findings = [];

  if (acao === "*" && acac === "true") {
    findings.push({
      finding: "CORS combines wildcard origin (*) with Access-Control-Allow-Credentials: true",
      severity: "High",
      owasp: "A05:2021 Security Misconfiguration",
      recommendation: "Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true.",
      location: url,
    });
  } else if (acao === testOrigin) {
    findings.push({
      finding: "Server reflects arbitrary Origin header in Access-Control-Allow-Origin",
      severity: acac === "true" ? "Critical" : "High",
      owasp: "A05:2021 Security Misconfiguration",
      recommendation: "Validate incoming Origin against an explicit allow-list rather than echoing back untrusted input.",
      location: url,
    });
  } else {
    findings.push({
      finding: "CORS does not echo back arbitrary origin headers",
      severity: "Info",
      location: url,
    });
  }
  return { acao, acac, findings };
}

/**
 * Checks for risky or unnecessary HTTP methods
 */
export async function checkHttpMethods(url) {
  const res = await safeFetch(url, { method: "OPTIONS" }).catch(() => null);
  if (!res) return { findings: [] };
  const allow = res.headers.get("allow") || "";
  const methods = allow
    .split(",")
    .map((m) => m.trim().toUpperCase())
    .filter(Boolean);
  const risky = methods.filter((m) => ["PUT", "DELETE", "TRACE", "CONNECT"].includes(m));
  const findings = risky.length
    ? [
        {
          finding: `Potentially risky HTTP methods advertised via OPTIONS: ${risky.join(", ")}`,
          severity: "Medium",
          owasp: "A05:2021 Security Misconfiguration",
          recommendation: "Disable unnecessary HTTP methods (PUT, DELETE, TRACE) at the web server/gateway level.",
          location: url,
        },
      ]
    : [{ finding: "No risky HTTP methods (PUT/DELETE/TRACE/CONNECT) advertised via OPTIONS", severity: "Info", location: url }];
  return { allow, methods, findings };
}

export const COMMON_DIRS = ["/images/", "/uploads/", "/backup/", "/assets/", "/files/", "/static/"];
export const DIR_LISTING_SIGNATURES = [
  /Index of \//i,
  /<title>Directory Listing/i,
  /<h1>Index of /i,
  /\[To Parent Directory\]/i,
  /<pre><a href="[\.\/]/i,
  /Volume Serial Number is/i,
];

/**
 * Checks for enabled directory listing on common paths
 */
export async function checkDirectoryListing(origin) {
  const findings = [];
  await Promise.all(
    COMMON_DIRS.map(async (dir) => {
      try {
        const res = await safeFetch(origin + dir, { redirect: "manual" });
        if (res.status === 200) {
          const body = await readBodyWithLimit(res, 16384);
          if (DIR_LISTING_SIGNATURES.some((sig) => sig.test(body))) {
            findings.push({
              finding: `Directory listing enabled at ${dir}`,
              severity: "Medium",
              owasp: "A05:2021 Security Misconfiguration",
              recommendation: "Disable directory autoindexing in web server configuration (e.g. 'Options -Indexes' in Apache, 'autoindex off' in Nginx).",
              location: origin + dir,
            });
          }
        }
      } catch {
        /* skip */
      }
    })
  );
  return { findings };
}

/**
 * Probes for stack traces and debug diagnostics on 404/error responses
 */
export async function checkErrorFingerprint(origin) {
  const probePath = "/mcp-probe-" + Math.random().toString(36).slice(2, 10);
  const res = await safeFetch(origin + probePath).catch(() => null);
  if (!res) return { findings: [] };
  const body = await readBodyWithLimit(res, 32768);
  const signatures = [
    /at\s+[\w.$]+\s+\(.*:\d+:\d+\)/,
    /Traceback \(most recent call last\)/i,
    /Fatal error:/i,
    /Whitelabel Error Page/i,
    /System\.Exception/i,
    /Stack trace:/i,
    /Microsoft OLE DB Provider/i,
    /Django Version:/i,
  ];
  const matched = signatures.some((re) => re.test(body));
  const findings = matched
    ? [
        {
          finding: "Error/404 page exposes internal framework stack traces or debug diagnostics",
          severity: "Medium",
          owasp: "A05:2021 Security Misconfiguration",
          recommendation: "Disable debug mode in production and configure generic custom error pages.",
          location: origin + probePath,
        },
      ]
    : [{ finding: "Error pages return sanitized responses without debug traces", severity: "Info", location: origin }];
  return { status: res.status, findings };
}

/**
 * Evaluates TLS protocol and certificate expiration
 */
export function checkTls(hostname, port = 443) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 5000 },
      () => {
        if (settled) return;
        settled = true;
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const findings = [];

        if (protocol === "TLSv1" || protocol === "TLSv1.1") {
          findings.push({
            finding: `Outdated cryptographic protocol supported: ${protocol}`,
            severity: "High",
            owasp: "A02:2021 Cryptographic Failures",
            recommendation: "Enforce TLS 1.2 or TLS 1.3 exclusively and disable legacy TLS 1.0/1.1.",
            location: hostname,
          });
        } else if (protocol) {
          findings.push({ finding: `TLS protocol in use: ${protocol}`, severity: "Info", location: hostname });
        }

        let daysToExpiry = null;
        if (cert && cert.valid_to) {
          daysToExpiry = Math.round((new Date(cert.valid_to) - Date.now()) / 86400000);
          if (daysToExpiry < 0) {
            findings.push({
              finding: "TLS certificate is expired",
              severity: "Critical",
              owasp: "A02:2021 Cryptographic Failures",
              recommendation: "Renew and deploy a valid TLS certificate immediately.",
              location: hostname,
            });
          } else if (daysToExpiry < 30) {
            findings.push({
              finding: `TLS certificate will expire in ${daysToExpiry} day(s)`,
              severity: "Medium",
              owasp: "A02:2021 Cryptographic Failures",
              recommendation: "Renew the TLS certificate prior to expiration.",
              location: hostname,
            });
          } else {
            findings.push({
              finding: `TLS certificate is valid for ${daysToExpiry} more day(s)`,
              severity: "Info",
              location: hostname,
            });
          }
        }
        socket.end();
        resolve({ protocol, cipher: socket.getCipher()?.name, validTo: cert?.valid_to, daysToExpiry, findings });
      }
    );

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

// ---------------------------------------------------------------------------
// Parameter-Level Checks
// ---------------------------------------------------------------------------

/**
 * Probes for reflected input and distinguishes HTML XSS indicators from API responses
 */
export async function checkReflectedInput(url, paramName) {
  const canary = `mcpProbe1<>"'`;
  const target = new URL(url);
  target.searchParams.set(paramName, canary);
  const res = await safeFetch(target.toString());
  const contentType = (res.headers.get("content-type") || "").toLowerCase();
  const body = await readBodyWithLimit(res, 65536);

  const reflectedRaw = body.includes(canary);
  const reflectedEscaped =
    body.includes("mcpProbe1&lt;&gt;&quot;&#39;") ||
    body.includes("mcpProbe1&lt;&gt;&#34;&#39;") ||
    body.includes("mcpProbe1&lt;&gt;&quot;&apos;");

  let finding;
  if (reflectedRaw) {
    if (contentType.includes("text/html") || contentType.includes("application/xhtml+xml") || !contentType) {
      finding = {
        finding: `Parameter '${paramName}' is reflected unencoded in an HTML response`,
        severity: "High",
        owasp: "A03:2021 Injection",
        recommendation: "Contextually output-encode all user input before rendering inside HTML templates.",
        location: target.toString(),
      };
    } else {
      finding = {
        finding: `Parameter '${paramName}' is reflected in '${contentType}' response (non-HTML context)`,
        severity: "Info",
        location: target.toString(),
      };
    }
  } else if (reflectedEscaped) {
    finding = {
      finding: `Parameter '${paramName}' is reflected with HTML entities encoded`,
      severity: "Info",
      location: target.toString(),
    };
  } else {
    finding = {
      finding: `Parameter '${paramName}' was not observed reflected in response body`,
      severity: "Info",
      location: target.toString(),
    };
  }
  return { findings: [finding] };
}

export const SQL_ERROR_SIGNATURES = [
  /you have an error in your sql syntax/i,
  /warning: mysql/i,
  /unclosed quotation mark/i,
  /ORA-\d{5}/i,
  /PostgreSQL.*ERROR/i,
  /SQLite3?::/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /pg_query\(\)/i,
  /SQLSTATE\[\w+\]/i,
  /CLI Driver.*DB2/i,
  /Sybase message/i,
  /Dynamic SQL Error/i,
];

/**
 * Checks for error-based SQL injection indicators using a single benign apostrophe
 */
export async function checkSqlErrorSignatures(url, paramName) {
  const target = new URL(url);
  target.searchParams.set(paramName, `test'`);
  const res = await safeFetch(target.toString());
  const body = await readBodyWithLimit(res, 65536);
  const matched = SQL_ERROR_SIGNATURES.filter((re) => re.test(body));
  const finding = matched.length
    ? {
        finding: `Parameter '${paramName}' triggered a database syntax error signature`,
        severity: "Critical",
        owasp: "A03:2021 Injection",
        recommendation: "Use parameterized queries (prepared statements) or ORM abstraction. Do not concatenate raw input into SQL statements.",
        evidence: matched.map(String),
        location: target.toString(),
      }
    : {
        finding: `No database syntax errors detected for parameter '${paramName}'`,
        severity: "Info",
        location: target.toString(),
      };
  return { findings: [finding] };
}

/**
 * Checks for open redirects using benign probe targets
 */
export async function checkOpenRedirect(url, paramName) {
  const probe = "https://example.org/mcp-redirect-probe";
  const target = new URL(url);
  target.searchParams.set(paramName, probe);
  const res = await safeFetch(target.toString(), { redirect: "manual" });
  const location = res.headers.get("location") || "";

  const vulnerable =
    res.status >= 300 &&
    res.status < 400 &&
    (location.startsWith(probe) || location.startsWith("//example.org"));

  const finding = vulnerable
    ? {
        finding: `Parameter '${paramName}' triggers an unvalidated redirect to external destination (${location})`,
        severity: "Medium",
        owasp: "A01:2021 Broken Access Control",
        recommendation: "Restrict redirect targets to relative internal paths or an explicit domain whitelist.",
        location: target.toString(),
      }
    : {
        finding: `No open redirect behavior observed for parameter '${paramName}'`,
        severity: "Info",
        location: target.toString(),
      };
  return { findings: [finding] };
}

/**
 * Decodes and inspects JSON Web Tokens (JWT) for cryptographic hygiene weaknesses
 */
export function decodeJwt(token) {
  const parts = token.trim().split(".");
  if (parts.length < 2) {
    return {
      error: "Invalid JWT format (expected dot-separated base64url segments)",
    };
  }
  const decodeSegment = (seg) => {
    try {
      return JSON.parse(Buffer.from(seg.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    } catch {
      return null;
    }
  };

  const header = decodeSegment(parts[0]);
  const payload = decodeSegment(parts[1]);
  const findings = [];

  if (!header || !payload) {
    return {
      error: "Failed to parse JWT segments as JSON",
    };
  }

  // Algorithm checks
  const alg = String(header?.alg || "").toLowerCase();
  if (alg === "none") {
    findings.push({
      finding: `JWT specifies alg: "${header.alg}" - unsigned tokens should never be accepted`,
      severity: "Critical",
      owasp: "A02:2021 Cryptographic Failures",
      recommendation: "Reject tokens with alg: none server-side; enforce signature verification using an explicit allow-list of algorithms.",
    });
  } else if (/^hs/i.test(header?.alg)) {
    findings.push({
      finding: `JWT uses symmetric HMAC algorithm (${header.alg})`,
      severity: "Low",
      owasp: "A02:2021 Cryptographic Failures",
      recommendation: "Verify that the HMAC secret has high entropy (>= 256 bits), or adopt asymmetric algorithms (RS256, ES256) across distributed services.",
    });
  } else if (header?.alg) {
    findings.push({ finding: `JWT specifies algorithm ${header.alg}`, severity: "Info" });
  }

  // Expiration checks
  if (!payload.exp) {
    findings.push({
      finding: "JWT payload does not specify an 'exp' (expiration) claim",
      severity: "Medium",
      owasp: "A07:2021 Identification and Authentication Failures",
      recommendation: "Always set an explicit expiration time on issued tokens to limit replay windows.",
    });
  } else if (payload.exp) {
    const expDate = new Date(payload.exp * 1000);
    if (expDate < new Date()) {
      findings.push({
        finding: `JWT is expired (${expDate.toISOString()}) but was active/available`,
        severity: "Low",
        owasp: "A07:2021 Identification and Authentication Failures",
        recommendation: "Ensure expired tokens are promptly rejected by backend authorizers.",
      });
    } else {
      findings.push({ finding: `JWT valid until ${expDate.toISOString()}`, severity: "Info" });
    }
  }

  // Sensitive payload information disclosure check
  const sensitiveKeys = ["password", "secret", "private_key", "ssn", "api_key"];
  const leakedKeys = sensitiveKeys.filter((k) => Object.prototype.hasOwnProperty.call(payload, k));
  if (leakedKeys.length > 0) {
    findings.push({
      finding: `JWT payload contains sensitive field name(s): ${leakedKeys.join(", ")}`,
      severity: "High",
      owasp: "A04:2021 Insecure Design",
      recommendation: "Never store credentials or sensitive plaintext secrets in unencrypted JWT payloads.",
    });
  }

  return { header, payload, findings };
}

// ---------------------------------------------------------------------------
// MCP Server Factory
// ---------------------------------------------------------------------------
export function createMcpServer() {
  const server = new McpServer({ name: "security-scan-mcp", version: "2.2.0" });

  server.tool(
    "scan_origin",
    "Runs a full battery of non-destructive origin-level security checks in parallel: security headers, cookie flags, sensitive/leaked file paths, CORS misconfiguration, risky HTTP methods, directory listing, TLS/certificate health, and error-page fingerprinting. Returns ONE consolidated, severity-sorted report with OWASP Top 10 mapping.",
    {
      url: z
        .string()
        .url()
        .max(2048)
        .describe("Any URL on the target origin, e.g. https://example.com/ or https://example.com/page"),
    },
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
        isHttps
          ? checkTls(hostname).catch((e) => ({ findings: [], error: e.message }))
          : Promise.resolve({ skipped: "target is not HTTPS", findings: [] }),
      ]);

      const all = [
        ...headers.findings,
        ...cookies.findings,
        ...sensitive.findings,
        ...cors.findings,
        ...methods.findings,
        ...dirs.findings,
        ...errFp.findings,
        ...tls_.findings,
      ];
      const { findings, passed, summary } = sortAndSplit(all);
      const result = {
        origin,
        scannedAt: new Date().toISOString(),
        score: headers.score,
        grade: headers.grade,
        checksRun: [
          "security_headers",
          "cookies",
          "sensitive_paths",
          "cors",
          "http_methods",
          "directory_listing",
          "error_fingerprint",
          isHttps ? "tls" : "tls_skipped_not_https",
        ],
        summary,
        findings,
        passed,
      };
      cacheSet(cacheKey, result);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "scan_parameter",
    "Runs all non-destructive parameter-level probes in parallel for a single query parameter: reflected-input (XSS indicator), SQL error signatures (injection indicator), and open-redirect. Returns ONE consolidated report with OWASP mapping.",
    {
      url: z.string().url().max(2048),
      paramName: z
        .string()
        .min(1)
        .max(128)
        .regex(/^[a-zA-Z0-9_\-\.\[\]]+$/, "Invalid parameter name format")
        .describe("Query parameter name observed on the page (e.g. 'q' or 'redirect')."),
    },
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
      const result = {
        url,
        paramName,
        checksRun: ["reflected_input", "sql_error_signatures", "open_redirect"],
        summary,
        findings,
        passed,
      };
      cacheSet(cacheKey, result);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "decode_jwt",
    "Decodes a JWT header and payload (base64) and flags security weaknesses: alg:none, weak symmetric algorithm usage, missing or expired 'exp' claim, and sensitive payload disclosures. Passive decoding only - does not attempt to crack or forge tokens.",
    {
      token: z
        .string()
        .min(10)
        .max(16384)
        .describe("The raw JWT string (e.g. from a cookie or Authorization header)"),
    },
    async ({ token }) => {
      const decoded = decodeJwt(token);
      return { content: [{ type: "text", text: JSON.stringify(decoded, null, 2) }] };
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// Express HTTP / SSE Transport
// ---------------------------------------------------------------------------
export const app = express();
export const transports = new Map();

// Authentication middleware
app.use((req, res, next) => {
  if (AUTH_TOKEN) {
    const authHeader = req.headers.authorization;
    const bearerMatch = authHeader && authHeader.match(/^Bearer\s+(.*)$/i);
    const token = (bearerMatch ? bearerMatch[1] : null) || req.query.token;

    if (token !== AUTH_TOKEN) {
      return res.status(401).json({ error: "Unauthorized: Invalid or missing authentication token." });
    }
  }

  // Cross-Origin / Origin validation
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.length > 0) {
    if (!ALLOWED_ORIGINS.includes(origin.toLowerCase())) {
      return res.status(403).json({ error: "Forbidden: Origin not permitted." });
    }
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  next();
});

app.get("/sse", async (req, res) => {
  const server = createMcpServer();
  const transport = new SSEServerTransport("/messages", res);
  transports.set(transport.sessionId, transport);

  res.on("close", () => {
    transports.delete(transport.sessionId);
  });

  await server.connect(transport);
});

app.post("/messages", async (req, res) => {
  const sessionId = req.query.sessionId;
  const transport = transports.get(sessionId);
  if (transport) {
    await transport.handlePostMessage(req, res);
  } else {
    res.status(400).send("No active transport found for provided sessionId");
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    version: "2.2.0",
    uptime: process.uptime(),
    ssrfProtection: !ALLOW_PRIVATE_TARGETS,
    authenticated: Boolean(AUTH_TOKEN),
  });
});

// Self-execution check for direct CLI execution
const isMainModule = process.argv[1] && url.fileURLToPath(import.meta.url) === process.argv[1];

if (isMainModule) {
  app.listen(PORT, HOST, () => {
    console.log(`security-scan-mcp v2.2.0 listening at http://${HOST}:${PORT}/sse`);
    console.log(`Network Interface: ${HOST} (Set HOST=0.0.0.0 for Docker container setups)`);
    console.log(`SSRF Protection: ${ALLOW_PRIVATE_TARGETS ? "DISABLED (ALLOW_PRIVATE_TARGETS=1)" : "ENABLED (blocks private/loopback IPs)"}`);
    console.log(`Authentication: ${AUTH_TOKEN ? "ENABLED" : "NONE (Localhost trusted)"}`);
    console.log("Tools available: scan_origin, scan_parameter, decode_jwt");
  });
}
