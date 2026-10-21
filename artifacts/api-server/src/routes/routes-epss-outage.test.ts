// EPSS is best-effort enrichment: a FIRST.org outage must not fail CVE responses.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { GetWeeklyCvesResponse } from "@workspace/api-zod";
import { startTestServer, healthyUpstream, type TestServer } from "../test-support/fake-upstreams";

let srv: TestServer;

before(async () => {
  srv = await startTestServer((url) =>
    url.hostname === "api.first.org" ? new Response("down", { status: 503 }) : healthyUpstream(url),
  );
});
after(async () => {
  await srv.close();
});

test("GET /api/cves/weekly still succeeds with null EPSS when FIRST.org is down", async () => {
  const res = await fetch(srv.baseUrl + "/api/cves/weekly");
  assert.equal(res.status, 200);
  const cves = GetWeeklyCvesResponse.parse(await res.json());
  assert.equal(cves.length, 3);
  assert.ok(cves.every((c) => c.epssScore === null && c.epssPercentile === null));
});

test("EPSS failure is recorded in /api/metrics", async () => {
  const res = await fetch(srv.baseUrl + "/api/metrics");
  const body = (await res.json()) as any;
  assert.match(body.lastError.epss.message, /EPSS fetch failed: 503/);
});
