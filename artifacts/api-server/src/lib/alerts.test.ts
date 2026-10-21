import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { notifyNewZeroDays, seedAlertBaseline, resetAlertState, formatAlert } from "./alerts";
import type { CveEntry } from "../routes/cves";

process.env.LOG_LEVEL ??= "silent";

function cve(id: string, opts: Partial<CveEntry> = {}): CveEntry {
  return {
    cveId: id,
    description: `Description of ${id}`,
    publishedDate: "2026-10-20T00:00:00.000",
    lastModifiedDate: "2026-10-20T00:00:00.000",
    severity: "CRITICAL",
    cvssScore: 9.8,
    cvssVector: null,
    hasKnownPatch: false,
    isKnownExploited: true,
    affectedProducts: [],
    patchUrls: [],
    references: [],
    vendor: "examplecorp",
    cweIds: [],
    platforms: ["Windows"],
    deviceType: "Endpoint",
    ...opts,
  };
}

const realFetch = globalThis.fetch;
let sent: Array<{ url: string; body: { text: string; content: string } }>;
let webhookStatus: number;

beforeEach(() => {
  resetAlertState();
  sent = [];
  webhookStatus = 200;
  process.env.ALERT_WEBHOOK_URL = "https://hooks.example.test/services/T000/B000/secret";
  delete process.env.ALERT_PLATFORMS;
  delete process.env.ALERT_DASHBOARD_URL;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    sent.push({ url: String(input), body: JSON.parse(String(init?.body)) });
    return new Response("ok", { status: webhookStatus });
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  delete process.env.ALERT_WEBHOOK_URL;
});

test("does nothing when ALERT_WEBHOOK_URL is unset", async () => {
  delete process.env.ALERT_WEBHOOK_URL;
  await notifyNewZeroDays([cve("CVE-2026-1000")]);
  await notifyNewZeroDays([cve("CVE-2026-1000"), cve("CVE-2026-1001")]);
  assert.equal(sent.length, 0);
});

test("first refresh seeds silently; later refreshes alert only new zero-days, once", async () => {
  await notifyNewZeroDays([cve("CVE-2026-1000")]);
  assert.equal(sent.length, 0);

  await notifyNewZeroDays([cve("CVE-2026-1000"), cve("CVE-2026-1001")]);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body.text, /CVE-2026-1001/);
  assert.doesNotMatch(sent[0].body.text, /CVE-2026-1000/);
  assert.equal(sent[0].body.content, sent[0].body.text);

  await notifyNewZeroDays([cve("CVE-2026-1000"), cve("CVE-2026-1001")]);
  assert.equal(sent.length, 1);
});

test("patched or non-exploited CVEs are not zero-days", async () => {
  seedAlertBaseline([]);
  await notifyNewZeroDays([
    cve("CVE-2026-2000", { hasKnownPatch: true }),
    cve("CVE-2026-2001", { isKnownExploited: false }),
  ]);
  assert.equal(sent.length, 0);
});

test("a snapshot-seeded baseline still alerts zero-days that appeared during downtime", async () => {
  seedAlertBaseline([cve("CVE-2026-3000")]);
  await notifyNewZeroDays([cve("CVE-2026-3000"), cve("CVE-2026-3001")]);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body.text, /CVE-2026-3001/);
  assert.doesNotMatch(sent[0].body.text, /CVE-2026-3000/);
});

test("ALERT_PLATFORMS filters (case-insensitive)", async () => {
  process.env.ALERT_PLATFORMS = "macos, linux";
  seedAlertBaseline([]);
  await notifyNewZeroDays([cve("CVE-2026-4000", { platforms: ["Windows"] }), cve("CVE-2026-4001", { platforms: ["macOS"] })]);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body.text, /CVE-2026-4001/);
  assert.doesNotMatch(sent[0].body.text, /CVE-2026-4000/);
});

test("a failed webhook is retried on the next refresh", async () => {
  seedAlertBaseline([]);
  webhookStatus = 500;
  await notifyNewZeroDays([cve("CVE-2026-5000")]);
  webhookStatus = 200;
  await notifyNewZeroDays([cve("CVE-2026-5000")]);
  assert.equal(sent.length, 2);
  await notifyNewZeroDays([cve("CVE-2026-5000")]);
  assert.equal(sent.length, 2);
});

test("upstream text can't inject Slack mentions or links", () => {
  const text = formatAlert([cve("CVE-2026-6000", { description: "evil <!channel> <https://x.test|click> & more", vendor: "<@U123>" })]);
  assert.doesNotMatch(text, /<!channel>|<@U123>|<https:\/\/x\.test/);
  assert.match(text, /&lt;!channel&gt;/);
  assert.match(text, /&amp; more/);
});

test("links go to the dashboard when ALERT_DASHBOARD_URL is set, otherwise NVD", () => {
  assert.match(formatAlert([cve("CVE-2026-7000")]), /<https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2026-7000\|CVE-2026-7000>/);
  assert.match(
    formatAlert([cve("CVE-2026-7000")], "https://patch.example.test"),
    /<https:\/\/patch\.example\.test\/cve\/CVE-2026-7000\|CVE-2026-7000>/,
  );
});

test("long batches are capped with a remainder line", () => {
  const many = Array.from({ length: 20 }, (_, i) => cve(`CVE-2026-8${String(i).padStart(3, "0")}`));
  const text = formatAlert(many);
  assert.match(text, /^:rotating_light: 20 new/);
  assert.match(text, /…and 5 more$/);
});
