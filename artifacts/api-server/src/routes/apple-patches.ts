import { Router, type IRouter, type Request, type Response } from "express";
import { logger } from "../lib/logger";
import * as metrics from "../lib/metrics";

const router: IRouter = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

interface AppleRelease {
  version: string | null;
  updateName: string | null;
  releaseDate: string;
  cveCount: number;
  securityInfoUrl: string | null;
  activelyExploited: boolean;
}

interface ApplePlatformDigest {
  platform: "ios" | "macos";
  releasesFound: number;
  willCombine: boolean;
  releases: AppleRelease[];
}

interface ApplePatchesResult {
  platforms: ApplePlatformDigest[];
  fetchedAt: string;
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

// ─── Cache ────────────────────────────────────────────────────────────────────

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}
const cache = new Map<string, CacheEntry<unknown>>();
function getCache<T>(key: string): T | null {
  const e = cache.get(key);
  if (!e || Date.now() > e.expiresAt) {
    cache.delete(key);
    metrics.recordCacheMiss(key);
    return null;
  }
  metrics.recordCacheHit(key);
  return e.data as T;
}
function setCache<T>(key: string, data: T, ttlMs: number) {
  cache.set(key, { data, expiresAt: Date.now() + ttlMs });
}

// Upstream is rate-limited to 10 req/hour in production, so cache generously.
const PATCHES_TTL = 30 * 60 * 1000; // 30 min
// The full HTML report is a heavier upstream call than /preview (it enriches every
// CVE by scraping Apple's advisory pages), so it gets a longer TTL.
const REPORT_TTL = 60 * 60 * 1000; // 1h

const VALID_PLATFORMS = new Set(["ios", "macos"]);

// ─── Upstream fetch ───────────────────────────────────────────────────────────

async function fetchPlatformDigest(platform: "ios" | "macos"): Promise<ApplePlatformDigest> {
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

async function fetchApplePatches(): Promise<ApplePatchesResult> {
  const cached = getCache<ApplePatchesResult>("apple_patches");
  if (cached) return cached;

  try {
    const platforms = await Promise.all([fetchPlatformDigest("ios"), fetchPlatformDigest("macos")]);
    const result: ApplePatchesResult = { platforms, fetchedAt: new Date().toISOString() };
    setCache("apple_patches", result, PATCHES_TTL);
    metrics.recordFetchSuccess("applePatches");
    return result;
  } catch (err) {
    metrics.recordFetchError("applePatches", err);
    throw err;
  }
}

async function fetchPlatformReport(platform: "ios" | "macos"): Promise<string> {
  const cacheKey = `apple_report_${platform}`;
  const cached = getCache<string>(cacheKey);
  if (cached) return cached;

  const baseUrl = process.env.APPLE_VULN_API_URL;
  const apiKey = process.env.APPLE_VULN_API_KEY;
  if (!baseUrl || !apiKey) {
    throw new Error("APPLE_VULN_API_URL / APPLE_VULN_API_KEY not configured");
  }

  try {
    logger.info({ platform }, "Fetching Apple vuln formatter full report");
    // Non-bare: includes NVD/advisory links, which /bare deliberately strips.
    const res = await fetch(`${baseUrl}/api/report/${platform}`, {
      headers: { "X-API-Key": apiKey, Accept: "text/html" },
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) throw new Error(`Apple vuln formatter report/${platform} failed: ${res.status}`);

    const html = await res.text();
    setCache(cacheKey, html, REPORT_TTL);
    metrics.recordFetchSuccess(`appleReport_${platform}`);
    return html;
  } catch (err) {
    metrics.recordFetchError(`appleReport_${platform}`, err);
    throw err;
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

router.get("/apple/patches", async (req: Request, res: Response) => {
  try {
    const result = await fetchApplePatches();
    res.json(result);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch Apple patch data");
    res.status(502).json({ error: "Failed to fetch Apple patch data" });
  }
});

router.get("/apple/report/:platform", async (req: Request, res: Response) => {
  const platform = req.params["platform"];
  if (typeof platform !== "string" || !VALID_PLATFORMS.has(platform)) {
    res.status(400).json({ error: "platform must be 'ios' or 'macos'" });
    return;
  }
  try {
    const html = await fetchPlatformReport(platform as "ios" | "macos");
    res.type("html").send(html);
  } catch (err) {
    req.log.error({ err, platform }, "Failed to fetch Apple full report");
    res.status(502).json({ error: "Failed to fetch Apple report" });
  }
});

export default router;
