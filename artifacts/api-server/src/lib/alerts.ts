import { logger } from "./logger";
import * as metrics from "./metrics";
import type { CveEntry } from "../routes/cves";

// Webhook alerts for newly appearing zero-days — CVEs that are actively exploited (in CISA KEV)
// with no known patch, the same definition as the dashboard's Zero-Days page.
//
// Config (all optional; alerts are off unless ALERT_WEBHOOK_URL is set):
//   ALERT_WEBHOOK_URL    Slack-compatible incoming webhook (also works with Mattermost; Discord
//                        reads the duplicated `content` field).
//   ALERT_PLATFORMS      Comma-separated platform filter, e.g. "Windows,macOS". Default: all.
//   ALERT_DASHBOARD_URL  Public dashboard origin; when set, CVE IDs link to /cve/{id} there
//                        instead of NVD.
//
// "Already alerted" is tracked in memory. At startup it's seeded from the last Postgres snapshot
// (seedAlertBaseline), so zero-days that appeared while the server was down still alert but old
// ones aren't re-sent after every restart. Without Postgres, the first live refresh seeds it
// silently. A failed webhook leaves the CVEs unmarked so the next refresh retries them.

const MAX_LISTED = 15;

let alerted: Set<string> | null = null;

const isZeroDay = (c: CveEntry) => c.isKnownExploited && !c.hasKnownPatch;

function config() {
  const webhookUrl = process.env.ALERT_WEBHOOK_URL?.trim();
  const platforms = (process.env.ALERT_PLATFORMS ?? "")
    .split(",")
    .map((p) => p.trim().toLowerCase())
    .filter(Boolean);
  const dashboardUrl = process.env.ALERT_DASHBOARD_URL?.trim().replace(/\/+$/, "");
  return { webhookUrl, platforms, dashboardUrl };
}

function matchesPlatforms(c: CveEntry, platforms: string[]): boolean {
  return platforms.length === 0 || c.platforms.some((p) => platforms.includes(p.toLowerCase()));
}

/** Seeds the "already alerted" set from previously persisted data without sending anything. */
export function seedAlertBaseline(entries: CveEntry[]): void {
  alerted = new Set(entries.filter(isZeroDay).map((c) => c.cveId));
  logger.info({ count: alerted.size }, "Seeded zero-day alert baseline");
}

// Slack mrkdwn treats <...> as links/mentions (e.g. <!channel>) and & as an entity; CVE text comes
// from upstream feeds, so escape it per Slack's formatting docs.
const escapeMrkdwn = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const truncate = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function formatAlert(cves: CveEntry[], dashboardUrl?: string): string {
  const header = `:rotating_light: ${cves.length} new actively exploited, unpatched CVE${cves.length === 1 ? "" : "s"} (CISA KEV, no known patch)`;
  const lines = cves.slice(0, MAX_LISTED).map((c) => {
    const link = dashboardUrl ? `${dashboardUrl}/cve/${c.cveId}` : `https://nvd.nist.gov/vuln/detail/${c.cveId}`;
    const facts = [
      c.severity ?? "UNSCORED",
      c.cvssScore != null ? `CVSS ${c.cvssScore}` : null,
      c.epssScore != null ? `EPSS ${(c.epssScore * 100).toFixed(1)}%` : null,
      c.vendor ? escapeMrkdwn(c.vendor) : null,
    ].filter(Boolean);
    return `• <${link}|${c.cveId}> — ${facts.join(" · ")}\n    ${escapeMrkdwn(truncate(c.description, 180))}`;
  });
  if (cves.length > MAX_LISTED) lines.push(`…and ${cves.length - MAX_LISTED} more`);
  return [header, ...lines].join("\n");
}

/**
 * Called after every weekly refresh. Sends one webhook message listing zero-days not alerted
 * before (filtered by ALERT_PLATFORMS). Never throws.
 */
export async function notifyNewZeroDays(entries: CveEntry[]): Promise<void> {
  const { webhookUrl, platforms, dashboardUrl } = config();
  if (!webhookUrl) return;

  if (!alerted) {
    seedAlertBaseline(entries);
    return;
  }

  const fresh = entries.filter((c) => isZeroDay(c) && !alerted!.has(c.cveId) && matchesPlatforms(c, platforms));
  if (fresh.length === 0) return;

  const text = formatAlert(fresh, dashboardUrl);
  try {
    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text, content: text }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error(`Alert webhook failed: ${res.status}`);
    for (const c of fresh) alerted.add(c.cveId);
    metrics.recordFetchSuccess("alerts");
    logger.info({ count: fresh.length, cveIds: fresh.map((c) => c.cveId) }, "Sent zero-day alert");
  } catch (err) {
    // Webhook URL deliberately not logged — it's a credential.
    metrics.recordFetchError("alerts", err);
    logger.warn({ err, count: fresh.length }, "Zero-day alert failed; will retry next refresh");
  }
}

/** Test hook: forget all alert state. */
export function resetAlertState(): void {
  alerted = null;
}
