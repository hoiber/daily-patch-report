// Route-level tests: the real Express app (routing, rate limiter, validation, caching, KEV
// cross-referencing) against fake NVD / CISA upstreams — see test-support/fake-upstreams.ts.
// Responses are also checked against the generated OpenAPI response schemas, so a handler
// drifting from openapi.yaml fails here rather than in the dashboard.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  GetWeeklyCvesResponse,
  GetDailyCvesResponse,
  GetKevListResponse,
  GetCveByIdResponse,
  GetCvesSearchResponse,
  HealthCheckResponse,
} from "@workspace/api-zod";
import { startTestServer, type TestServer } from "../test-support/fake-upstreams";

let srv: TestServer;
const get = async (path: string) => {
  const res = await fetch(srv.baseUrl + path);
  return { status: res.status, body: (await res.json()) as any };
};

before(async () => {
  srv = await startTestServer();
});
after(async () => {
  await srv.close();
});

test("GET /api/healthz", async () => {
  const { status, body } = await get("/api/healthz");
  assert.equal(status, 200);
  HealthCheckResponse.parse(body);
});

test("GET /api/cves/weekly returns every fixture CVE, matching the OpenAPI schema", async () => {
  const { status, body } = await get("/api/cves/weekly");
  assert.equal(status, 200);
  const cves = GetWeeklyCvesResponse.parse(body);
  assert.deepEqual(cves.map((c) => c.cveId).sort(), ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]);
});

test("GET /api/cves/weekly sorts patched first, then by severity", async () => {
  const { body } = await get("/api/cves/weekly");
  // 0001 (patched, CRITICAL), 0003 (patched, HIGH), 0002 (unpatched)
  assert.deepEqual(body.map((c: { cveId: string }) => c.cveId), ["CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0002"]);
});

test("GET /api/cves/weekly cross-references CISA KEV onto isKnownExploited", async () => {
  const { body } = await get("/api/cves/weekly");
  const byId = Object.fromEntries(body.map((c: { cveId: string; isKnownExploited: boolean }) => [c.cveId, c.isKnownExploited]));
  assert.deepEqual(byId, { "CVE-2026-0001": false, "CVE-2026-0002": true, "CVE-2026-0003": false });
});

test("GET /api/cves/weekly?severity=HIGH filters", async () => {
  const { status, body } = await get("/api/cves/weekly?severity=HIGH");
  assert.equal(status, 200);
  assert.deepEqual(body.map((c: { cveId: string }) => c.cveId), ["CVE-2026-0003"]);
});

test("GET /api/cves/weekly?patchedOnly=true filters", async () => {
  const { body } = await get("/api/cves/weekly?patchedOnly=true");
  assert.ok(body.every((c: { hasKnownPatch: boolean }) => c.hasKnownPatch));
  assert.equal(body.length, 2);
});

test("GET /api/cves/daily only includes CVEs published in the last 24h", async () => {
  const { status, body } = await get("/api/cves/daily");
  assert.equal(status, 200);
  const cves = GetDailyCvesResponse.parse(body);
  assert.deepEqual(cves.map((c) => c.cveId).sort(), ["CVE-2026-0001", "CVE-2026-0003"]);
});

test("weekly data is cached: repeat requests don't re-hit NVD", async () => {
  const before = srv.upstreamCalls.filter((u) => u.includes("cvssV3Severity")).length;
  await get("/api/cves/weekly");
  await get("/api/cves/daily");
  const afterCount = srv.upstreamCalls.filter((u) => u.includes("cvssV3Severity")).length;
  assert.equal(afterCount, before);
});

test("GET /api/cves/kev returns the KEV catalog, matching the OpenAPI schema", async () => {
  const { status, body } = await get("/api/cves/kev");
  assert.equal(status, 200);
  const kev = GetKevListResponse.parse(body);
  assert.equal(kev.length, 1);
  assert.equal(kev[0].cveId, "CVE-2026-0002");
  assert.equal(kev[0].cvssScore, 9.1); // enriched from NVD's hasKev query
});

test("GET /api/cves/:cveId serves a cached CVE with KEV details", async () => {
  const { status, body } = await get("/api/cves/CVE-2026-0002");
  assert.equal(status, 200);
  const cve = GetCveByIdResponse.parse(body);
  assert.equal(cve.cveId, "CVE-2026-0002");
  assert.equal(cve.kevDetails?.vendorProject, "ExampleCorp");
});

test("GET /api/cves/:cveId returns 404 for an unknown CVE", async () => {
  const { status, body } = await get("/api/cves/CVE-1999-9999");
  assert.equal(status, 404);
  assert.deepEqual(body, { error: "CVE not found" });
});

test("GET /api/cves/search falls back to the in-memory cache without Postgres", async () => {
  const { status, body } = await get("/api/cves/search?q=chrome");
  assert.equal(status, 200);
  assert.deepEqual(GetCvesSearchResponse.parse(body).map((c) => c.cveId), ["CVE-2026-0003"]);
});

test("GET /api/cves/trend returns [] without Postgres", async () => {
  const { status, body } = await get("/api/cves/trend?days=30");
  assert.equal(status, 200);
  assert.deepEqual(body, []);
});

// ─── Validation → 400 ────────────────────────────────────────────────────────

for (const [path, field] of [
  ["/api/cves/weekly?severity=BOGUS", "severity"],
  ["/api/cves/daily?severity=critical", "severity"],
  ["/api/cves/trend?days=abc", "days"],
  ["/api/cves/trend?days=3.5", "days"],
  ["/api/cves/search", "q"],
  ["/api/cves/changes?field=nope", "field"],
  ["/api/cves/kev?limit=lots", "limit"],
] as const) {
  test(`GET ${path} -> 400 naming '${field}'`, async () => {
    const { status, body } = await get(path);
    assert.equal(status, 400);
    assert.match(body.error, new RegExp(`\\b${field}\\b`));
  });
}

test("400 responses never echo the submitted value back", async () => {
  const marker = "<script>alert(1)</script>";
  const { status, body } = await get(`/api/cves/weekly?severity=${encodeURIComponent(marker)}`);
  assert.equal(status, 400);
  assert.ok(!JSON.stringify(body).includes("script"));
});

test("GET /api/apple/cves/:platform/:version rejects unknown platforms", async () => {
  const { status } = await get("/api/apple/cves/android/14");
  assert.equal(status, 400);
});
