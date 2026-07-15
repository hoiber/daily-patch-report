import { Router, type IRouter, type Request, type Response } from "express";
import { logger } from "../lib/logger";
import * as metrics from "../lib/metrics";
import { saveAppleRelease, loadLatestAppleReleases, loadAppleReleaseHistory, loadAppleReleaseCves } from "../lib/apple-store";

const router: IRouter = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

type Platform = "ios" | "macos";

interface AppleRelease {
  version: string | null;
  updateName: string | null;
  releaseDate: string;
  cveCount: number;
  securityInfoUrl: string | null;
  activelyExploited: boolean;
}

interface ApplePlatformDigest {
  platform: Platform;
  releasesFound: number;
  willCombine: boolean;
  releases: AppleRelease[];
}

interface ApplePatchesResult {
  platforms: ApplePlatformDigest[];
  fetchedAt: string;
}

interface AppleCve {
  cveId: string;
  description: string | null;
  activelyExploited: boolean;
  versionNote: string | null;
  nvdUrl: string;
}

interface UpstreamPreviewRelease {
  version: string | null;
  update_name: string | null;
  release_date: string;
  cve_count: number;
  security_info_url: string | null;
  actively_exploited: boolean;
}

interface UpstreamPreviewResponse {
  releases_found: number;
  will_combine: boolean;
  releases: UpstreamPreviewRelease[];
}

const VALID_PLATFORMS = new Set(["ios", "macos"]);

// ─── Upstream fetch ───────────────────────────────────────────────────────────

async function fetchPlatformDigest(platform: Platform): Promise<ApplePlatformDigest> {
  const baseUrl = process.env.APPLE_VULN_API_URL;
  const apiKey = process.env.APPLE_VULN_API_KEY;
  if (!baseUrl || !apiKey) {
    throw new Error("APPLE_VULN_API_URL / APPLE_VULN_API_KEY not configured");
  }

  logger.info({ platform }, "Fetching Apple vuln formatter preview");
  const res = await fetch(`${baseUrl}/api/preview/${platform}`, {
    headers: { "X-API-Key": apiKey, Accept: "application/json" },
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`Apple vuln formatter preview/${platform} failed: ${res.status}`);

  const json = (await res.json()) as UpstreamPreviewResponse;

  return {
    platform,
    releasesFound: json.releases_found,
    willCombine: json.will_combine,
    releases: (json.releases ?? []).map((r) => ({
      version: r.version ?? null,
      updateName: r.update_name ?? null,
      releaseDate: r.release_date,
      cveCount: r.cve_count,
      securityInfoUrl: r.security_info_url ?? null,
      activelyExploited: r.actively_exploited,
    })),
  };
}

async function fetchPlatformReportHtml(platform: Platform): Promise<string> {
  const baseUrl = process.env.APPLE_VULN_API_URL;
  const apiKey = process.env.APPLE_VULN_API_KEY;
  if (!baseUrl || !apiKey) {
    throw new Error("APPLE_VULN_API_URL / APPLE_VULN_API_KEY not configured");
  }

  logger.info({ platform }, "Fetching Apple vuln formatter full report");
  // Non-bare: includes NVD links, which /bare deliberately strips — needed to parse CVE detail below.
  const res = await fetch(`${baseUrl}/api/report/${platform}`, {
    headers: { "X-API-Key": apiKey, Accept: "text/html" },
    signal: AbortSignal.timeout(30000),
  });
  if (!res.ok) throw new Error(`Apple vuln formatter report/${platform} failed: ${res.status}`);
  return res.text();
}

// Matches each risk-detail entry in the report's "Risk to your business" block, e.g.:
//   <a href='https://nvd.nist.gov/vuln/detail/CVE-2026-1234' ...>CVE-2026-1234</a>
//   <span ...>[ACTIVELY EXPLOITED]</span><span ...>[iOS 18.7.3 only]</span>: Some impact text<br><br>
// See ReportBuilder.build_html_report in the ios-security-vulnerability-formatter repo for the source format.
const CVE_ENTRY_RE =
  /<a href='https:\/\/nvd\.nist\.gov\/vuln\/detail\/(CVE-\d{4}-\d+)'[^>]*>\1<\/a>((?:\s*<span[^>]*>\[[^\]]*\]<\/span>)*)\s*:?\s*([\s\S]*?)(?=<br><br>|$)/g;

function stripHtmlTags(s: string): string {
  return s.replace(/<[^>]+>/g, "").trim();
}

function parseCvesFromReportHtml(html: string): AppleCve[] {
  const cves: AppleCve[] = [];
  const seen = new Set<string>();

  for (const m of html.matchAll(CVE_ENTRY_RE)) {
    const cveId = m[1] as string;
    if (seen.has(cveId)) continue; // the same link can't legitimately repeat, but guard regardless
    seen.add(cveId);

    const spans = m[2] ?? "";
    const versionMatch = spans.match(/\[([^\]]+?)\s+only\]/i);
    const description = stripHtmlTags(m[3] ?? "");

    cves.push({
      cveId,
      description: description || null,
      activelyExploited: /ACTIVELY EXPLOITED/i.test(spans),
      versionNote: versionMatch ? (versionMatch[1] as string) : null,
      nvdUrl: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    });
  }

  return cves;
}

async function fetchPlatformCves(platform: Platform): Promise<AppleCve[]> {
  const html = await fetchPlatformReportHtml(platform);
  return parseCvesFromReportHtml(html);
}

// ─── In-memory "current" cache, updated only by refreshApplePatches ───────────
//
// Unlike the other routes in this file's siblings (cves.ts, patch-tuesday.ts),
// this isn't a TTL-lazy cache — reads never trigger an upstream fetch on their
// own. Freshness is entirely owned by the scheduled daily job and the manual
// refresh endpoint below, so the upstream tool's rate limit (10 req/hour in
// production) is never at risk regardless of dashboard traffic.

let currentSnapshot: ApplePatchesResult | null = null;
const currentCves: Record<Platform, AppleCve[]> = { ios: [], macos: [] };

async function refreshPlatform(platform: Platform): Promise<{ digest: ApplePlatformDigest; cves: AppleCve[] }> {
  const digest = await fetchPlatformDigest(platform);
  const cves = await fetchPlatformCves(platform);

  const primary = digest.releases[0];
  if (primary) {
    await saveAppleRelease(platform, primary, cves);
  }

  return { digest, cves };
}

/** Live fetch for both platforms, persisted to Postgres and swapped into the in-memory "current" cache. */
export async function refreshApplePatches(): Promise<ApplePatchesResult> {
  try {
    logger.info("Refreshing Apple patch data");
    const [ios, macos] = await Promise.all([refreshPlatform("ios"), refreshPlatform("macos")]);

    const result: ApplePatchesResult = {
      platforms: [ios.digest, macos.digest],
      fetchedAt: new Date().toISOString(),
    };
    currentSnapshot = result;
    currentCves.ios = ios.cves;
    currentCves.macos = macos.cves;

    metrics.recordFetchSuccess("applePatches");
    logger.info("Apple patch data refreshed");
    return result;
  } catch (err) {
    metrics.recordFetchError("applePatches", err);
    throw err;
  }
}

let warmupInFlight: Promise<void> | null = null;

/** Cold-start / DB-empty fallback: ensures there's *something* to serve before the first scheduled run. */
async function ensureWarm(): Promise<void> {
  if (currentSnapshot) return;
  if (!warmupInFlight) {
    warmupInFlight = refreshApplePatches()
      .then(() => {})
      .catch((err) => logger.warn({ err }, "Apple patch warmup fetch failed"))
      .finally(() => {
        warmupInFlight = null;
      });
  }
  await warmupInFlight;
}

/**
 * One-time cold-start warmup — call after server starts (see index.ts). Warms
 * from Postgres immediately if there's a persisted release, then only pays for
 * a live fetch if that snapshot is missing or stale enough that the daily
 * schedule must have been missed (e.g. the service was down at 07:00 AEST).
 */
export async function warmApplePatches(): Promise<void> {
  const latest = await loadLatestAppleReleases();
  const platforms: ApplePlatformDigest[] = [];
  let newestLastSeenAt = 0;

  for (const platform of ["ios", "macos"] as const) {
    const entry = latest[platform];
    if (!entry) continue;
    platforms.push({
      platform,
      releasesFound: 1,
      willCombine: false,
      releases: [
        {
          version: entry.release.version,
          updateName: entry.release.updateName,
          releaseDate: entry.release.releaseDate,
          cveCount: entry.release.cveCount,
          securityInfoUrl: entry.release.securityInfoUrl,
          activelyExploited: entry.release.activelyExploited,
        },
      ],
    });
    currentCves[platform] = entry.cves;
    newestLastSeenAt = Math.max(newestLastSeenAt, new Date(entry.release.lastSeenAt).getTime());
  }

  if (platforms.length > 0) {
    currentSnapshot = { platforms, fetchedAt: new Date(newestLastSeenAt).toISOString() };
    logger.info({ platforms: platforms.length }, "Warmed Apple patch cache from Postgres");
  }

  // Missed the last scheduled run entirely (no data) or it's been long enough
  // that the daily 07:00 AEST tick must have been missed (e.g. downtime) — catch up now.
  const STALE_MS = 20 * 60 * 60 * 1000; // 20h
  const isStale = newestLastSeenAt === 0 || Date.now() - newestLastSeenAt > STALE_MS;
  if (isStale) {
    await refreshApplePatches().catch((err) => logger.warn({ err }, "Apple patch catch-up fetch failed"));
  }
}

// ─── Daily schedule (07:00 AEST, fixed UTC+10 — no DST adjustment) ───────────

const AEST_OFFSET_HOURS = 10;
const DAILY_FETCH_HOUR_AEST = 7;
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

function msUntilNextDailyFetch(): number {
  const now = new Date();
  const targetUtcHour = (DAILY_FETCH_HOUR_AEST - AEST_OFFSET_HOURS + 24) % 24;
  const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), targetUtcHour, 0, 0, 0));
  if (next.getTime() <= now.getTime()) next.setUTCDate(next.getUTCDate() + 1);
  return next.getTime() - now.getTime();
}

/** Call once after server start (see index.ts) to arm the recurring 07:00 AEST refresh. */
export function scheduleAppleDailyFetch(): void {
  const delay = msUntilNextDailyFetch();
  logger.info({ nextRunAt: new Date(Date.now() + delay).toISOString() }, "Scheduled next daily Apple patch fetch");

  setTimeout(() => {
    void refreshApplePatches().catch((err) => logger.warn({ err }, "Scheduled Apple patch fetch failed"));
    setInterval(() => {
      void refreshApplePatches().catch((err) => logger.warn({ err }, "Scheduled Apple patch fetch failed"));
    }, ONE_DAY_MS);
  }, delay);
}

// ─── Manual refresh cooldown ───────────────────────────────────────────────────

const MANUAL_REFRESH_COOLDOWN_MS = 5 * 60 * 1000;
let lastManualRefreshAt = 0;

// ─── Routes ───────────────────────────────────────────────────────────────────

router.get("/apple/patches", async (req: Request, res: Response) => {
  try {
    await ensureWarm();
    res.json(currentSnapshot ?? { platforms: [], fetchedAt: new Date().toISOString() });
  } catch (err) {
    req.log.error({ err }, "Failed to fetch Apple patch data");
    res.status(502).json({ error: "Failed to fetch Apple patch data" });
  }
});

router.get("/apple/cves/:platform/:version", async (req: Request, res: Response) => {
  const platform = req.params["platform"];
  const version = req.params["version"];
  if (typeof platform !== "string" || !VALID_PLATFORMS.has(platform)) {
    res.status(400).json({ error: "platform must be 'ios' or 'macos'" });
    return;
  }
  if (typeof version !== "string" || version.length === 0) {
    res.status(400).json({ error: "version is required" });
    return;
  }
  try {
    await ensureWarm();
    const p = platform as Platform;

    // Persisted per-version detail covers any version we've ever fetched, current or historical.
    const stored = await loadAppleReleaseCves(p, version);
    if (stored !== null) {
      res.json({ cves: stored });
      return;
    }

    // Postgres not configured (or this version predates it being set up) — the in-memory
    // cache only ever holds the live latest, so it can only answer for that exact version.
    const currentVersion = currentSnapshot?.platforms.find((d) => d.platform === p)?.releases[0]?.version;
    res.json({ cves: version === currentVersion ? currentCves[p] : [] });
  } catch (err) {
    req.log.error({ err, platform, version }, "Failed to fetch Apple CVE detail");
    res.status(502).json({ error: "Failed to fetch Apple CVE detail" });
  }
});

router.get("/apple/history/:platform", async (req: Request, res: Response) => {
  const platform = req.params["platform"];
  if (typeof platform !== "string" || !VALID_PLATFORMS.has(platform)) {
    res.status(400).json({ error: "platform must be 'ios' or 'macos'" });
    return;
  }
  try {
    const history = await loadAppleReleaseHistory(platform as Platform, 50);
    res.json({ history });
  } catch (err) {
    req.log.error({ err, platform }, "Failed to fetch Apple release history");
    res.status(502).json({ error: "Failed to fetch Apple release history" });
  }
});

router.post("/apple/refresh", async (req: Request, res: Response) => {
  const now = Date.now();
  const sinceLast = now - lastManualRefreshAt;
  if (sinceLast < MANUAL_REFRESH_COOLDOWN_MS) {
    const retryAfterSeconds = Math.ceil((MANUAL_REFRESH_COOLDOWN_MS - sinceLast) / 1000);
    res.set("Retry-After", String(retryAfterSeconds));
    res.status(429).json({ error: "Refreshed too recently", retryAfterSeconds });
    return;
  }

  lastManualRefreshAt = now;
  try {
    const result = await refreshApplePatches();
    res.json(result);
  } catch (err) {
    req.log.error({ err }, "Manual Apple patch refresh failed");
    res.status(502).json({ error: "Failed to refresh Apple patch data" });
  }
});

export default router;
