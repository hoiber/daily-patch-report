import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { notifyAlerts, seedAlertBaseline, resetAlertState, formatAlert } from "./alerts";
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
  for (const key of ["ALERT_PLATFORMS", "ALERT_VENDORS", "ALERT_EVENTS", "ALERT_MIN_SEVERITY", "ALERT_MIN_EPSS"]) {
    delete process.env[key];
  }
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
  await notifyAlerts([cve("CVE-2026-1000")]);
  await notifyAlerts([cve("CVE-2026-1000"), cve("CVE-2026-1001")]);
  assert.equal(sent.length, 0);
});

test("first refresh seeds silently; later refreshes alert only new zero-days, once", async () => {
  await notifyAlerts([cve("CVE-2026-1000")]);
  assert.equal(sent.length, 0);

  await notifyAlerts([cve("CVE-2026-1000"), cve("CVE-2026-1001")]);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body.text, /CVE-2026-1001/);
  assert.doesNotMatch(sent[0].body.text, /CVE-2026-1000/);
  assert.equal(sent[0].body.content, sent[0].body.text);

  await notifyAlerts([cve("CVE-2026-1000"), cve("CVE-2026-1001")]);
  assert.equal(sent.length, 1);
});

test("patched or non-exploited CVEs are not zero-days", async () => {
  seedAlertBaseline([]);
  await notifyAlerts([
    cve("CVE-2026-2000", { hasKnownPatch: true }),
    cve("CVE-2026-2001", { isKnownExploited: false }),
  ]);
  assert.equal(sent.length, 0);
});

test("a snapshot-seeded baseline still alerts zero-days that appeared during downtime", async () => {
  seedAlertBaseline([cve("CVE-2026-3000")]);
  await notifyAlerts([cve("CVE-2026-3000"), cve("CVE-2026-3001")]);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body.text, /CVE-2026-3001/);
  assert.doesNotMatch(sent[0].body.text, /CVE-2026-3000/);
});

test("ALERT_PLATFORMS filters (case-insensitive)", async () => {
  process.env.ALERT_PLATFORMS = "macos, linux";
  seedAlertBaseline([]);
  await notifyAlerts([cve("CVE-2026-4000", { platforms: ["Windows"] }), cve("CVE-2026-4001", { platforms: ["macOS"] })]);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body.text, /CVE-2026-4001/);
  assert.doesNotMatch(sent[0].body.text, /CVE-2026-4000/);
});

test("a failed webhook is retried on the next refresh", async () => {
  seedAlertBaseline([]);
  webhookStatus = 500;
  await notifyAlerts([cve("CVE-2026-5000")]);
  webhookStatus = 200;
  await notifyAlerts([cve("CVE-2026-5000")]);
  assert.equal(sent.length, 2);
  await notifyAlerts([cve("CVE-2026-5000")]);
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

const recently = () => new Date(Date.now() - 3600_000).toISOString();
const benign = { isKnownExploited: false, hasKnownPatch: true };

test("the default config only sends zero-days", async () => {
  seedAlertBaseline([]);
  await notifyAlerts([
    cve("CVE-2026-9000", { hasKnownPatch: true }),
    cve("CVE-2026-9001", { ...benign, publishedDate: recently() }),
  ]);
  assert.equal(sent.length, 0);
});

test("ALERT_VENDORS matches vendor or product, case-insensitively, for every event", async () => {
  process.env.ALERT_VENDORS = "Fortinet, chrome";
  seedAlertBaseline([]);
  await notifyAlerts([
    cve("CVE-2026-9100", { vendor: "fortinet" }),
    cve("CVE-2026-9101", { vendor: "google", affectedProducts: ["google/chrome"] }),
    cve("CVE-2026-9102", { vendor: "acme" }),
    cve("CVE-2026-9103", { vendor: null }),
  ]);
  assert.match(sent[0].body.text, /CVE-2026-9100/);
  assert.match(sent[0].body.text, /CVE-2026-9101/);
  assert.doesNotMatch(sent[0].body.text, /CVE-2026-9102|CVE-2026-9103/);
});

test("kev fires for patched CVEs, and a zero-day is listed once under its most urgent event", async () => {
  process.env.ALERT_EVENTS = "zero-day,kev";
  seedAlertBaseline([]);
  await notifyAlerts([cve("CVE-2026-9200", { hasKnownPatch: true }), cve("CVE-2026-9201")]);
  const { text } = sent[0].body;
  assert.match(text, /1 new actively exploited[\s\S]*CVE-2026-9201[\s\S]*1 CVE newly added to CISA KEV[\s\S]*CVE-2026-9200/);
  assert.equal(text.match(/^• .*CVE-2026-9201/gm)?.length, 1);
});

test("a CVE that gains a patch after a zero-day alert doesn't alert again", async () => {
  process.env.ALERT_EVENTS = "zero-day,kev";
  seedAlertBaseline([]);
  await notifyAlerts([cve("CVE-2026-9250")]);
  await notifyAlerts([cve("CVE-2026-9250", { hasKnownPatch: true })]);
  assert.equal(sent.length, 1);
});

test("severity alerts on a raise, not on the first score or a drop", async () => {
  process.env.ALERT_EVENTS = "severity";
  seedAlertBaseline([
    cve("CVE-2026-9300", { ...benign, severity: "MEDIUM" }),
    cve("CVE-2026-9301", { ...benign, severity: null }),
    cve("CVE-2026-9302", { ...benign, severity: "HIGH" }),
  ]);
  await notifyAlerts([
    cve("CVE-2026-9300", { ...benign, severity: "HIGH" }),
    cve("CVE-2026-9301", { ...benign, severity: "CRITICAL" }),
    cve("CVE-2026-9302", { ...benign, severity: "LOW" }),
  ]);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body.text, /^:arrow_up: 1 CVE raised/);
  assert.match(sent[0].body.text, /CVE-2026-9300/);
  assert.doesNotMatch(sent[0].body.text, /CVE-2026-9301|CVE-2026-9302/);

  await notifyAlerts([cve("CVE-2026-9300", { ...benign, severity: "CRITICAL" })]);
  assert.equal(sent.length, 2);
});

test("a severity raise survives a failed webhook", async () => {
  process.env.ALERT_EVENTS = "severity";
  seedAlertBaseline([cve("CVE-2026-9350", { ...benign, severity: "LOW" })]);
  webhookStatus = 500;
  await notifyAlerts([cve("CVE-2026-9350", { ...benign, severity: "HIGH" })]);
  webhookStatus = 200;
  await notifyAlerts([cve("CVE-2026-9350", { ...benign, severity: "HIGH" })]);
  await notifyAlerts([cve("CVE-2026-9350", { ...benign, severity: "HIGH" })]);
  assert.equal(sent.length, 2);
});

test("new applies thresholds, skips old CVEs, and catches a CVE once it's scored", async () => {
  process.env.ALERT_EVENTS = "new";
  process.env.ALERT_MIN_SEVERITY = "high";
  process.env.ALERT_MIN_EPSS = "0.5";
  seedAlertBaseline([]);
  const fresh = { ...benign, publishedDate: recently() };
  await notifyAlerts([
    cve("CVE-2026-9400", { ...fresh, severity: "CRITICAL", epssScore: 0.9 }),
    cve("CVE-2026-9401", { ...fresh, severity: "CRITICAL", epssScore: 0.1 }),
    cve("CVE-2026-9402", { ...fresh, severity: "LOW", epssScore: 0.9 }),
    cve("CVE-2026-9403", { ...benign, severity: "CRITICAL", epssScore: 0.9 }),
    cve("CVE-2026-9404", { ...fresh, severity: null, epssScore: 0.9 }),
  ]);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body.text, /CVE-2026-9400/);
  assert.doesNotMatch(sent[0].body.text, /CVE-2026-940[1-4]/);

  await notifyAlerts([cve("CVE-2026-9404", { ...fresh, severity: "HIGH", epssScore: 0.9 })]);
  assert.equal(sent.length, 2);
  assert.match(sent[1].body.text, /CVE-2026-9404/);
});

test("thresholds never hold back an unscored zero-day", async () => {
  process.env.ALERT_MIN_SEVERITY = "CRITICAL";
  process.env.ALERT_MIN_EPSS = "0.9";
  seedAlertBaseline([]);
  await notifyAlerts([cve("CVE-2026-9500", { severity: null, cvssScore: null })]);
  assert.equal(sent.length, 1);
  assert.match(sent[0].body.text, /UNSCORED/);
});

test("a restart doesn't re-send what the snapshot already holds", async () => {
  process.env.ALERT_EVENTS = "zero-day,kev,new";
  const snapshot = [cve("CVE-2026-9600", { publishedDate: recently() })];
  seedAlertBaseline(snapshot);
  await notifyAlerts(snapshot);
  assert.equal(sent.length, 0);
});

test("invalid config falls back to safe defaults", async () => {
  process.env.ALERT_EVENTS = "bogus";
  process.env.ALERT_MIN_EPSS = "lots";
  process.env.ALERT_MIN_SEVERITY = "SPICY";
  seedAlertBaseline([]);
  await notifyAlerts([cve("CVE-2026-9700")]);
  assert.equal(sent.length, 1);
});
