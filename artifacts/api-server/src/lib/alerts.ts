import { logger } from "./logger";
import * as metrics from "./metrics";
import type { CveEntry } from "../routes/cves";

// Webhook alerts, evaluated after each weekly refresh. Each event fires at most once per CVE.
//
// Config (all optional; alerts are off unless ALERT_WEBHOOK_URL is set):
//   ALERT_WEBHOOK_URL    Slack-compatible incoming webhook (also works with Mattermost; Discord
//                        reads the duplicated `content` field).
//   ALERT_EVENTS         Comma-separated events to send. Default: zero-day.
//                          zero-day  actively exploited (in CISA KEV) with no known patch, the same
//                                    definition as the dashboard's Zero-Days page
//                          kev       added to CISA KEV, patched or not
//                          severity  severity went up (e.g. HIGH to CRITICAL)
//                          new       published in the last 7 days and passes the thresholds below
//   ALERT_PLATFORMS      Comma-separated platform filter, e.g. "Windows,macOS". Default: all.
//   ALERT_VENDORS        Comma-separated vendor/product filter, matched as a case-insensitive
//                        substring of the vendor and affected products. Default: all.
//   ALERT_MIN_SEVERITY   LOW, MEDIUM, HIGH or CRITICAL. Applies to `new` and `severity` only.
//   ALERT_MIN_EPSS       EPSS probability from 0 to 1. Applies to `new` and `severity` only.
//   ALERT_DASHBOARD_URL  Public dashboard origin; when set, CVE IDs link to /cve/{id} there
//                        instead of NVD.
//
// Platforms and vendors scope every event. The thresholds deliberately don't apply to zero-day or
// kev, because a brand-new exploited CVE often has no score yet and must still alert.
//
// "Already alerted" is tracked in memory. At startup it's seeded from the last Postgres snapshot
// (seedAlertBaseline), so CVEs that appeared while the server was down still alert but old ones
// aren't re-sent after every restart. Without Postgres, the first live refresh seeds it silently.
// A failed webhook leaves the CVEs unmarked so the next refresh retries them.

const MAX_LISTED = 15;
const NEW_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

const EVENTS = ["zero-day", "kev", "severity", "new"] as const;
type AlertEvent = (typeof EVENTS)[number];

const SEVERITY_RANK: Record<string, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

const HEADERS: Record<AlertEvent, (count: number, plural: string) => string> = {
  "zero-day": (n, s) => `:rotating_light: ${n} new actively exploited, unpatched CVE${s} (CISA KEV, no known patch)`,
  kev: (n, s) => `:warning: ${n} CVE${s} newly added to CISA KEV`,
  severity: (n, s) => `:arrow_up: ${n} CVE${s} raised in severity`,
  new: (n, s) => `:new: ${n} new CVE${s} matching your alert rules`,
};

let alerted: Set<string> | null = null;
const lastSeverity = new Map<string, string>();

const isZeroDay = (c: CveEntry) => c.isKnownExploited && !c.hasKnownPatch;
const severityRank = (c: CveEntry) => SEVERITY_RANK[c.severity ?? ""] ?? 0;

const csv = (raw: string | undefined) =>
  (raw ?? "")
    .split(",")
    .map((p) => p.trim().toLowerCase())
    .filter(Boolean);

function config() {
  const webhookUrl = process.env.ALERT_WEBHOOK_URL?.trim();
  const events = new Set(csv(process.env.ALERT_EVENTS).filter((e) => (EVENTS as readonly string[]).includes(e)));
  if (events.size === 0) events.add("zero-day");
  const minEpss = Number(process.env.ALERT_MIN_EPSS ?? 0);
  return {
    webhookUrl,
    events,
    platforms: csv(process.env.ALERT_PLATFORMS),
    vendors: csv(process.env.ALERT_VENDORS),
    minSeverity: SEVERITY_RANK[process.env.ALERT_MIN_SEVERITY?.trim().toUpperCase() ?? ""] ?? 0,
    minEpss: minEpss >= 0 && minEpss <= 1 ? minEpss : 0,
    dashboardUrl: process.env.ALERT_DASHBOARD_URL?.trim().replace(/\/+$/, ""),
  };
}

type Config = ReturnType<typeof config>;

function inScope(c: CveEntry, { platforms, vendors }: Config): boolean {
  if (platforms.length > 0 && !c.platforms.some((p) => platforms.includes(p.toLowerCase()))) return false;
  if (vendors.length === 0) return true;
  const names = [c.vendor ?? "", ...c.affectedProducts].map((n) => n.toLowerCase());
  return vendors.some((v) => names.some((n) => n.includes(v)));
}

function meetsThresholds(c: CveEntry, { minSeverity, minEpss }: Config): boolean {
  return severityRank(c) >= minSeverity && (minEpss === 0 || (c.epssScore ?? 0) >= minEpss);
}

const isRecent = (c: CveEntry) => Date.now() - new Date(c.publishedDate).getTime() <= NEW_WINDOW_MS;

function severityRaised(c: CveEntry): boolean {
  // An unknown previous severity isn't a raise: that's a CVE getting its first score.
  const previous = SEVERITY_RANK[lastSeverity.get(c.cveId) ?? ""];
  return previous !== undefined && severityRank(c) > previous;
}

/** The dedupe key for an event on a CVE, or null when it doesn't apply. */
function eventKey(event: AlertEvent, c: CveEntry, cfg: Config): string | null {
  switch (event) {
    case "zero-day":
      return isZeroDay(c) ? `zero-day:${c.cveId}` : null;
    case "kev":
      return c.isKnownExploited ? `kev:${c.cveId}` : null;
    case "severity":
      return severityRaised(c) && meetsThresholds(c, cfg) ? `severity:${c.cveId}:${c.severity}` : null;
    case "new":
      return isRecent(c) && meetsThresholds(c, cfg) ? `new:${c.cveId}` : null;
  }
}

function rememberSeverity(c: CveEntry): void {
  if (c.severity) lastSeverity.set(c.cveId, c.severity);
}

/** Seeds the "already alerted" state from previously persisted data without sending anything. */
export function seedAlertBaseline(entries: CveEntry[]): void {
  const { minSeverity } = config();
  alerted = new Set();
  for (const c of entries) {
    if (isZeroDay(c)) alerted.add(`zero-day:${c.cveId}`);
    if (c.isKnownExploited) alerted.add(`kev:${c.cveId}`);
    // Snapshots have no EPSS, so this can't check ALERT_MIN_EPSS. CVEs below the severity threshold
    // stay unmarked, so one that's later scored higher still alerts.
    if (severityRank(c) >= minSeverity) alerted.add(`new:${c.cveId}`);
    rememberSeverity(c);
  }
  logger.info({ count: alerted.size }, "Seeded alert baseline");
}

// Slack mrkdwn treats <...> as links/mentions (e.g. <!channel>) and & as an entity; CVE text comes
// from upstream feeds, so escape it per Slack's formatting docs.
const escapeMrkdwn = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const truncate = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function formatAlert(cves: CveEntry[], dashboardUrl?: string, event: AlertEvent = "zero-day"): string {
  const header = HEADERS[event](cves.length, cves.length === 1 ? "" : "s");
  const lines = cves.slice(0, MAX_LISTED).map((c) => {
    const link = dashboardUrl ? `${dashboardUrl}/cve/${c.cveId}` : `https://nvd.nist.gov/vuln/detail/${c.cveId}`;
    const facts = [
      c.severity ?? "UNSCORED",
      c.cvssScore != null ? `CVSS ${c.cvssScore}` : null,
      c.epssScore != null ? `EPSS ${(c.epssScore * 100).toFixed(1)}%` : null,
      c.ssvcExploitation === "active" ? "SSVC: active exploitation" : null,
      c.vendor ? escapeMrkdwn(c.vendor) : null,
    ].filter(Boolean);
    return `• <${link}|${c.cveId}> — ${facts.join(" · ")}\n    ${escapeMrkdwn(truncate(c.description, 180))}`;
  });
  if (cves.length > MAX_LISTED) lines.push(`…and ${cves.length - MAX_LISTED} more`);
  return [header, ...lines].join("\n");
}

/**
 * Called after every weekly refresh. Sends one webhook message covering everything not alerted
 * before, with each CVE listed once under its most urgent event. Never throws.
 */
export async function notifyAlerts(entries: CveEntry[]): Promise<void> {
  const cfg = config();
  if (!cfg.webhookUrl) return;

  if (!alerted) {
    seedAlertBaseline(entries);
    return;
  }

  const groups = new Map<AlertEvent, CveEntry[]>();
  const pendingKeys: string[] = [];
  const pendingIds = new Set<string>();

  for (const c of entries) {
    if (!inScope(c, cfg)) continue;
    for (const event of EVENTS) {
      if (!cfg.events.has(event)) continue;
      const key = eventKey(event, c, cfg);
      if (!key || alerted.has(key)) continue;
      pendingKeys.push(key);
      if (!pendingIds.has(c.cveId)) groups.set(event, [...(groups.get(event) ?? []), c]);
      pendingIds.add(c.cveId);
    }
  }

  let sent = pendingKeys.length === 0;
  if (!sent) {
    const text = EVENTS.filter((e) => groups.has(e))
      .map((e) => formatAlert(groups.get(e)!, cfg.dashboardUrl, e))
      .join("\n\n");
    try {
      const res = await fetch(cfg.webhookUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text, content: text }),
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`Alert webhook failed: ${res.status}`);
      for (const key of pendingKeys) alerted.add(key);
      sent = true;
      metrics.recordFetchSuccess("alerts");
      logger.info({ count: pendingIds.size, cveIds: [...pendingIds] }, "Sent CVE alert");
    } catch (err) {
      // Webhook URL deliberately not logged — it's a credential.
      metrics.recordFetchError("alerts", err);
      logger.warn({ err, count: pendingIds.size }, "CVE alert failed; will retry next refresh");
    }
  }

  // Unsent CVEs keep their old severity, so a severity raise is still detected on the retry.
  for (const c of entries) if (sent || !pendingIds.has(c.cveId)) rememberSeverity(c);
}

/** Test hook: forget all alert state. */
export function resetAlertState(): void {
  alerted = null;
  lastSeverity.clear();
}
