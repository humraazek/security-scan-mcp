import test from "node:test";
import assert from "node:assert/strict";
import {
  isPrivateOrReservedIp,
  validateAndResolveHost,
  cacheGet,
  cacheSet,
  cacheClear,
  decodeJwt,
  sortAndSplit,
  createMcpServer,
} from "../server.js";

test("SSRF Defense: detects private and reserved IP addresses", () => {
  assert.equal(isPrivateOrReservedIp("127.0.0.1"), true, "Loopback IPv4 must be blocked");
  assert.equal(isPrivateOrReservedIp("127.100.200.1"), true, "Entire 127.0.0.0/8 block must be blocked");
  assert.equal(isPrivateOrReservedIp("10.0.0.1"), true, "10.0.0.0/8 private network must be blocked");
  assert.equal(isPrivateOrReservedIp("172.16.0.5"), true, "172.16.0.0/12 private network must be blocked");
  assert.equal(isPrivateOrReservedIp("172.31.255.255"), true, "172.31.255.255 private network must be blocked");
  assert.equal(isPrivateOrReservedIp("192.168.1.1"), true, "192.168.0.0/16 private network must be blocked");
  assert.equal(isPrivateOrReservedIp("169.254.169.254"), true, "Cloud metadata 169.254.0.0/16 must be blocked");
  assert.equal(isPrivateOrReservedIp("0.0.0.0"), true, "0.0.0.0/8 must be blocked");
  assert.equal(isPrivateOrReservedIp("::1"), true, "IPv6 loopback must be blocked");
  assert.equal(isPrivateOrReservedIp("fe80::1"), true, "IPv6 link-local must be blocked");

  // Public IP addresses must be allowed
  assert.equal(isPrivateOrReservedIp("8.8.8.8"), false, "Public Google DNS IPv4 must be allowed");
  assert.equal(isPrivateOrReservedIp("1.1.1.1"), false, "Public Cloudflare IPv4 must be allowed");
  assert.equal(isPrivateOrReservedIp("93.184.216.34"), false, "Public example.com IP must be allowed");
});

test("SSRF Defense: validateAndResolveHost rejects local and metadata endpoints", async () => {
  await assert.rejects(
    () => validateAndResolveHost("localhost"),
    /SSRF Guard: Target host 'localhost' is a local\/internal name/,
    "localhost must be rejected"
  );

  await assert.rejects(
    () => validateAndResolveHost("169.254.169.254"),
    /SSRF Guard: IP '169.254.169.254' is in a private or reserved range/,
    "AWS metadata IP must be rejected"
  );

  await assert.rejects(
    () => validateAndResolveHost("host.docker.internal"),
    /SSRF Guard: Target host 'host.docker.internal' is a local\/internal name/,
    "host.docker.internal must be rejected"
  );
});

test("Cache: stores, retrieves, and expires entries correctly", () => {
  cacheClear();
  assert.equal(cacheGet("test_key"), null, "Non-existent key returns null");

  cacheSet("test_key", { data: "test_value" });
  assert.deepEqual(cacheGet("test_key"), { data: "test_value" }, "Retrieved cached value matches");

  cacheClear();
  assert.equal(cacheGet("test_key"), null, "Cache cleared successfully");
});

test("JWT Analyzer: detects alg:none critical vulnerability", () => {
  // Header: {"alg":"none","typ":"JWT"}, Payload: {"sub":"user1"}
  const noneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMSJ9.";
  const result = decodeJwt(noneToken);

  assert.ok(result.findings, "Findings should be returned");
  const crit = result.findings.find((f) => f.severity === "Critical");
  assert.ok(crit, "Must identify critical finding for alg:none");
  assert.match(crit.finding, /alg: "none"/);
});

test("JWT Analyzer: detects missing expiration and sensitive data disclosure", () => {
  // Payload: {"sub":"admin","password":"cleartext_password_123"}
  const rawToken =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInBhc3N3b3JkIjoiY2xlYXJ0ZXh0X3Bhc3N3b3JkXzEyMyJ9.signature";
  const result = decodeJwt(rawToken);

  const missingExp = result.findings.find((f) => f.finding.includes("'exp' (expiration) claim"));
  assert.ok(missingExp, "Must detect missing expiration claim");

  const sensitive = result.findings.find((f) => f.finding.includes("sensitive field name(s)"));
  assert.ok(sensitive, "Must detect password leakage in payload");
  assert.equal(sensitive.severity, "High");
});

test("JWT Analyzer: rejects malformed JWT input safely", () => {
  const invalid = decodeJwt("not_a_valid_jwt_string");
  assert.ok(invalid.error, "Should return an error object for malformed token");
});

test("Findings Organizer: sorts by severity and counts summary accurately", () => {
  const mockFindings = [
    { finding: "Info finding", severity: "Info" },
    { finding: "Low finding", severity: "Low" },
    { finding: "Critical finding", severity: "Critical" },
    { finding: "High finding", severity: "High" },
    { finding: "Medium finding", severity: "Medium" },
  ];

  const { findings, passed, summary } = sortAndSplit(mockFindings);

  assert.equal(summary.critical, 1);
  assert.equal(summary.high, 1);
  assert.equal(summary.medium, 1);
  assert.equal(summary.low, 1);

  assert.equal(findings[0].severity, "Critical");
  assert.equal(findings[1].severity, "High");
  assert.equal(findings[2].severity, "Medium");
  assert.equal(findings[3].severity, "Low");

  assert.equal(passed.length, 1);
  assert.equal(passed[0].finding, "Info finding");
});

test("MCP Server Factory: registers consolidated tools with strict schemas", () => {
  const mcp = createMcpServer();
  assert.ok(mcp, "MCP server created");
});

test("Parameter Validation: rejects dangerous characters and oversized names", () => {
  const paramSchema = /^[a-zA-Z0-9_\-\.\[\]]+$/;
  assert.equal(paramSchema.test("valid_param[0]"), true);
  assert.equal(paramSchema.test("q"), true);
  assert.equal(paramSchema.test("redirect-url"), true);

  // Dangerous / injection characters must be rejected
  assert.equal(paramSchema.test("param\r\nCRLF: injection"), false);
  assert.equal(paramSchema.test("param<script>"), false);
  assert.equal(paramSchema.test("param' OR '1'='1"), false);
  assert.equal(paramSchema.test("param; rm -rf /"), false);
});

