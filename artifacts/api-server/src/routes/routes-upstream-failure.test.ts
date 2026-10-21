// Upstream-failure behaviour, in its own file (node:test runs each file in a separate process)
// so the module-level caches start empty and every upstream call fails.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startTestServer, failingUpstream, type TestServer } from "../test-support/fake-upstreams";

let srv: TestServer;
const get = async (path: string) => {
  const res = await fetch(srv.baseUrl + path);
  return { status: res.status, body: (await res.json()) as any };
};

before(async () => {
  srv = await startTestServer(failingUpstream);
});
after(async () => {
  await srv.close();
});

test("GET /api/cves/kev -> 502 with a generic message when CISA is down", async () => {
  const { status, body } = await get("/api/cves/kev");
  assert.equal(status, 502);
  assert.deepEqual(body, { error: "Failed to fetch CISA KEV data" });
});

test("upstream error bodies are never reflected to clients", async () => {
  for (const path of ["/api/cves/kev", "/api/cves/weekly", "/api/cves/daily", "/api/cves/CVE-2026-0001"]) {
    const { status, body } = await get(path);
    assert.equal(status, 502, path);
    assert.ok(!JSON.stringify(body).includes("secret-internal-detail"), path);
  }
});

test("invalid params still return 400 (not 502) while upstreams are down", async () => {
  const { status } = await get("/api/cves/weekly?severity=BOGUS");
  assert.equal(status, 400);
});

test("/api/healthz stays up while upstreams are down", async () => {
  const { status } = await get("/api/healthz");
  assert.equal(status, 200);
});
