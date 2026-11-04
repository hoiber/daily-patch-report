// The weekly fetch's coverage guarantees, in its own file (node:test runs each file in a separate
// process) so it can script NVD responses against empty module-level caches.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startTestServer, healthyUpstream, nvdItem, type TestServer } from "../test-support/fake-upstreams";

const PAGE_SIZE = 2000;

const page1 = Array.from({ length: PAGE_SIZE }, (_, i) =>
  nvdItem({ id: `CVE-2026-${10000 + i}`, score: 5, publishedHoursAgo: 30, description: "Filler" }),
);
const lastPage = [
  nvdItem({ id: "CVE-2026-0100", score: 2.5, publishedHoursAgo: 3, description: "A LOW CVE" }),
  nvdItem({ id: "CVE-2026-0101", score: 9.3, publishedHoursAgo: 3, description: "Only a v4 score", cvssVersion: 4 }),
  nvdItem({ id: "CVE-2026-0102", score: null, publishedHoursAgo: 3, description: "Not scored" }),
  nvdItem({ id: "CVE-2026-0103", score: null, publishedHoursAgo: 3, description: "Withdrawn", vulnStatus: "Rejected" }),
];
const olderKev = nvdItem({ id: "CVE-2024-9999", score: 9.8, publishedHoursAgo: 24 * 400, description: "Old CVE, newly in KEV" });

let nvdDown = false;
let lastPageDown = false;

let srv: TestServer;
const weekly = async () => {
  const res = await fetch(`${srv.baseUrl}/api/cves/weekly`);
  return { status: res.status, body: (await res.json()) as any };
};
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });

before(async () => {
  srv = await startTestServer((url) => {
    if (url.hostname === "access.redhat.com") {
      return json([{ CVE: "CVE-2026-0102", advisories: ["RHSA-2026:1234"] }]);
    }
    if (url.hostname !== "services.nvd.nist.gov") return healthyUpstream(url);
    if (url.searchParams.has("pubStartDate")) {
      if (nvdDown) return new Response("down", { status: 503 });
      const first = url.searchParams.get("startIndex") === "0";
      if (!first && lastPageDown) return new Response("down", { status: 503 });
      return json({ totalResults: PAGE_SIZE + lastPage.length, vulnerabilities: first ? page1 : lastPage });
    }
    if (url.searchParams.has("kevStartDate")) return json({ totalResults: 1, vulnerabilities: [olderKev] });
    if (url.searchParams.has("lastModStartDate")) return json({ totalResults: 0, vulnerabilities: [] });
    return healthyUpstream(url);
  });
});
after(async () => {
  await srv.close();
});

test("fetches every page, with no severity filter", async () => {
  const { status, body } = await weekly();
  assert.equal(status, 200);
  assert.equal(body.length, PAGE_SIZE + 3);
  const calls = srv.upstreamCalls.filter((u) => u.includes("pubStartDate"));
  assert.equal(calls.length, 2);
  assert.ok(calls.every((u) => !u.includes("cvssV3Severity")));
});

test("includes LOW, v4-only and unscored CVEs", async () => {
  const { body } = await weekly();
  const byId = new Map(body.map((c: any) => [c.cveId, c])) as Map<string, any>;
  assert.equal(byId.get("CVE-2026-0100").severity, "LOW");
  assert.equal(byId.get("CVE-2026-0101").severity, "CRITICAL");
  assert.equal(byId.get("CVE-2026-0101").cvssScore, 9.3);
  assert.equal(byId.get("CVE-2026-0102").severity, null);
});

test("leaves out rejected CVEs, and older CVEs stay out of the weekly list", async () => {
  const ids = (await weekly()).body.map((c: { cveId: string }) => c.cveId);
  assert.ok(!ids.includes("CVE-2026-0103"));
  assert.ok(!ids.includes("CVE-2024-9999"));
});

test("a Red Hat erratum marks a CVE patched and links the fix", async () => {
  const cve = (await weekly()).body.find((c: { cveId: string }) => c.cveId === "CVE-2026-0102");
  assert.equal(cve.hasKnownPatch, true);
  assert.deepEqual(cve.patchUrls, ["https://access.redhat.com/errata/RHSA-2026:1234"]);
});

test("sends hasKev as a bare flag", () => {
  const call = srv.upstreamCalls.find((u) => u.includes("kevStartDate"));
  assert.match(call ?? "", /\?hasKev&kevStartDate=/);
});

test("a failed refresh keeps the last complete dataset instead of serving a partial one", async () => {
  const { refreshCveCache } = await import("./cves");
  lastPageDown = true;
  await refreshCveCache();
  lastPageDown = false;
  nvdDown = true;
  await refreshCveCache();
  nvdDown = false;
  assert.equal((await weekly()).body.length, PAGE_SIZE + 3);
});
