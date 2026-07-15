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

async function fetchPlatformReportHtml(platform: "ios" | "macos"): Promise<string> {
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

async function fetchPlatformCves(platform: "ios" | "macos"): Promise<AppleCve[]> {
  const cacheKey = `apple_cves_${platform}`;
  const cached = getCache<AppleCve[]>(cacheKey);
  if (cached) return cached;

  try {
    const html = await fetchPlatformReportHtml(platform);
    const cves = parseCvesFromReportHtml(html);
    setCache(cacheKey, cves, REPORT_TTL);
    metrics.recordFetchSuccess(`appleCves_${platform}`);
    return cves;
  } catch (err) {
    metrics.recordFetchError(`appleCves_${platform}`, err);
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

router.get("/apple/cves/:platform", async (req: Request, res: Response) => {
  const platform = req.params["platform"];
  if (typeof platform !== "string" || !VALID_PLATFORMS.has(platform)) {
    res.status(400).json({ error: "platform must be 'ios' or 'macos'" });
    return;
  }
  try {
    const cves = await fetchPlatformCves(platform as "ios" | "macos");
    res.json({ cves });
  } catch (err) {
    req.log.error({ err, platform }, "Failed to fetch Apple CVE detail");
    res.status(502).json({ error: "Failed to fetch Apple CVE detail" });
  }
});

export default router;
