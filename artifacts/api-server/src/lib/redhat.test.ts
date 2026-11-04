import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { getRedhatAdvisories, applyRedhatAdvisories, resetRedhatCache } from "./redhat";

process.env.LOG_LEVEL ??= "silent";

const realFetch = globalThis.fetch;
let calls: string[];
let respond: () => Response;

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

beforeEach(() => {
  resetRedhatCache();
  calls = [];
  respond = () => json([{ CVE: "CVE-2026-0001", advisories: ["RHSA-2026:1", "RHBA-2026:2", "evil/../x"] }]);
  globalThis.fetch = (async (input: string | URL | Request) => {
    calls.push(String(input));
    return respond();
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

test("keeps only well-formed RHSA IDs, and caches misses", async () => {
  const ids = ["CVE-2026-0001", "CVE-2026-0002"];
  const first = await getRedhatAdvisories(ids);
  assert.deepEqual([...first], [["CVE-2026-0001", ["RHSA-2026:1"]]]);
  await getRedhatAdvisories(ids);
  assert.equal(calls.length, 1);
});

test("batches lookups by 100", async () => {
  respond = () => json([]);
  await getRedhatAdvisories(Array.from({ length: 250 }, (_, i) => `CVE-2026-${10000 + i}`));
  assert.equal(calls.length, 3);
});

test("treats a 404 as no data, and stops on an outage without throwing", async () => {
  respond = () => json({}, 404);
  assert.equal((await getRedhatAdvisories(["CVE-2026-0003"])).size, 0);

  calls = [];
  respond = () => json({}, 503);
  const ids = Array.from({ length: 250 }, (_, i) => `CVE-2026-${20000 + i}`);
  assert.equal((await getRedhatAdvisories(ids)).size, 0);
  assert.equal(calls.length, 1);
});

test("an expired result outlives an outage, so a fixed CVE can't flip back to unpatched", async (t) => {
  await getRedhatAdvisories(["CVE-2026-0001"]);
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() + 25 * 3600_000 });
  respond = () => json({}, 503);
  assert.ok((await getRedhatAdvisories(["CVE-2026-0001"])).has("CVE-2026-0001"));
});

test("errata links go first and the list stays capped", () => {
  const existing = ["a", "b", "c", "d", "e"].map((x) => `https://example.com/${x}`);
  const [patched, untouched] = applyRedhatAdvisories(
    [
      { cveId: "CVE-2026-0001", hasKnownPatch: false, patchUrls: existing },
      { cveId: "CVE-2026-0002", hasKnownPatch: false, patchUrls: [] },
    ],
    new Map([["CVE-2026-0001", ["RHSA-2026:1"]]]),
  );
  assert.equal(patched.hasKnownPatch, true);
  assert.equal(patched.patchUrls[0], "https://access.redhat.com/errata/RHSA-2026:1");
  assert.equal(patched.patchUrls.length, 5);
  assert.equal(untouched.hasKnownPatch, false);
});
