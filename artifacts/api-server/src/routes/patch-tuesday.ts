import { Router, type IRouter, type Request, type Response } from "express";
import { GetPatchTuesdayDigestQueryParams } from "@workspace/api-zod";
import { logger } from "../lib/logger";
import { isSafeHttpUrl } from "../lib/url-safety";
import * as metrics from "../lib/metrics";

/** Collapses the per-release `pt_digest_<releaseId>` cache keys into one metrics bucket. */
function metricsKeyFor(cacheKey: string): string {
  return cacheKey.startsWith("pt_digest_") ? "pt_digest" : cacheKey;
}

const router: IRouter = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

interface PtRelease {
  id: string;
  title: string;
  releaseDate: string;
}

interface PtCve {
  cveId: string;
  title: string;
  description: string | null;
  severity: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  isExploited: boolean;
  isPubliclyDisclosed: boolean;
  affectedProducts: string[];
  kbArticles: string[];
  patchUrls: string[];
  impactType: string | null;
  attackVector: string | null;
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
    metrics.recordCacheMiss(metricsKeyFor(key));
    return null;
  }
  metrics.recordCacheHit(metricsKeyFor(key));
  return e.data as T;
}
function setCache<T>(key: string, data: T, ttlMs: number) {
  cache.set(key, { data, expiresAt: Date.now() + ttlMs });
}

const RELEASES_TTL = 6 * 60 * 60 * 1000;  // 6h
const DIGEST_TTL  = 60 * 60 * 1000;       // 1h

// ─── MSRC API helpers ─────────────────────────────────────────────────────────

const MSRC_BASE = "https://api.msrc.microsoft.com/cvrf/v2.0";

async function fetchReleases(): Promise<PtRelease[]> {
  const cached = getCache<PtRelease[]>("pt_releases");
  if (cached) return cached;

  try {
    return await doFetchReleases();
  } catch (err) {
    metrics.recordFetchError("ptReleases", err);
    throw err;
  }
}

async function doFetchReleases(): Promise<PtRelease[]> {
  logger.info("Fetching MSRC releases list");
  const res = await fetch(`${MSRC_BASE}/updates`, {
    headers: { Accept: "application/json", "User-Agent": "CVE-Daily-Report/1.0" },
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`MSRC updates failed: ${res.status}`);

  const json = (await res.json()) as {
    value: Array<{ ID: string; DocumentTitle: { Value: string }; InitialReleaseDate: string }>;
  };

  const releases: PtRelease[] = json.value
    .filter((r) => /^\d{4}-[A-Za-z]+$/.test(r.ID)) // only monthly IDs like 2024-Jun
    .map((r) => ({
      id: r.ID,
      title: r.DocumentTitle?.Value ?? r.ID,
      releaseDate: r.InitialReleaseDate?.split("T")[0] ?? "",
    }))
    .sort((a, b) => b.releaseDate.localeCompare(a.releaseDate))
    .slice(0, 12);

  setCache("pt_releases", releases, RELEASES_TTL);
  metrics.recordFetchSuccess("ptReleases");
  return releases;
}

// ─── CVRF document parsing ────────────────────────────────────────────────────

// Helper: normalise a property that may be a single object or an array
function toArray<T>(v: T | T[] | undefined): T[] {
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
}

interface CvrfProduct { ProductID: string; Value: string }

interface CvrfThreat {
  Type: number;
  Description: { Value: string } | string;
  ProductID?: string | string[];
}

interface CvrfRemediation {
  Type: number;
  Description?: { Value: string } | string;
  URL?: string;
  ProductID?: string | string[];
}

interface CvrfScoreSet {
  BaseScore?: string | number;
  TemporalScore?: string | number;
  Vector?: string;
  ProductID?: string | string[];
}

interface CvrfProductStatus {
  Type: number;
  ProductID?: string | string[];
}

// The MSRC CVRF v2 JSON API returns flat arrays for all these fields
interface CvrfVulnerability {
  CVE?: string;
  Title?: { Value: string } | string;
  Notes?: Array<{ Type: number; Value: string }>;
  CVSSScoreSets?: CvrfScoreSet[];
  ProductStatuses?: CvrfProductStatus[];
  Threats?: CvrfThreat[];
  Remediations?: CvrfRemediation[];
}

interface CvrfDocument {
  DocumentTitle?: { Value: string } | string;
  DocumentTracking?: {
    Identification?: { ID?: { Value: string } };
    InitialReleaseDate?: string;
    CurrentReleaseDate?: string;
  };
  ProductTree?: { FullProductName?: CvrfProduct | CvrfProduct[] };
  Vulnerability?: CvrfVulnerability | CvrfVulnerability[];
}

function strVal(v: { Value: string } | string | undefined): string {
  if (!v) return "";
  return typeof v === "string" ? v : v.Value ?? "";
}

function parseCvrf(doc: CvrfDocument, productMap: Map<string, string>): PtCve[] {
  const vulns = toArray(doc.Vulnerability);
  const results: PtCve[] = [];

  for (const vuln of vulns) {
    const cveId = vuln.CVE ?? "";
    if (!cveId) continue;

    const title = strVal(vuln.Title) || cveId;

    // Description — Notes is a flat array; Type 1 = FAQ/Description
    const notes = toArray(vuln.Notes);
    const descNote = notes.find((n) => n.Type === 1) ?? notes[0];
    const description = descNote?.Value ?? null;

    // CVSS — CVSSScoreSets is a flat array in MSRC CVRF v2 JSON
    const scoreSets = toArray(vuln.CVSSScoreSets);
    // Pick highest BaseScore
    const scoreSet = scoreSets.reduce<CvrfScoreSet | undefined>((best, ss) => {
      const s = parseFloat(String(ss.BaseScore ?? 0));
      const b = parseFloat(String(best?.BaseScore ?? 0));
      return s > b ? ss : best;
    }, undefined);
    const rawScore = scoreSet?.BaseScore;
    const cvssScore = rawScore != null ? parseFloat(String(rawScore)) : null;
    const cvssVector = scoreSet?.Vector ?? null;

    // Threats — flat array in MSRC CVRF v2 JSON
    // Type 0 = Impact type (e.g. "Elevation of Privilege")
    // Type 1 = Exploit status (e.g. "Publicly Disclosed:No;Exploited:No;...")
    // Type 3 = Severity per-product (e.g. "Important", "Critical")
    const threats = toArray(vuln.Threats);
    let severity: string | null = null;
    let impactType: string | null = null;
    let isExploited = false;
    let isPubliclyDisclosed = false;

    const SEVERITY_ORDER: Record<string, number> = { Critical: 0, Important: 1, Moderate: 2, Low: 3 };

    for (const t of threats) {
      const val = strVal(t.Description as { Value: string } | string | undefined);
      if (t.Type === 0) {
        // Impact type — take the first (most are the same across products)
        if (!impactType) impactType = val || null;
      } else if (t.Type === 1) {
        // Exploit status — semicolon-separated key:value pairs
        // e.g. "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Unlikely"
        const lower = val.toLowerCase();
        if (lower.includes("exploited:yes")) isExploited = true;
        if (lower.includes("publicly disclosed:yes")) isPubliclyDisclosed = true;
      } else if (t.Type === 3) {
        // Severity per product — pick highest across all products
        const order = SEVERITY_ORDER[val] ?? 99;
        const currentOrder = SEVERITY_ORDER[severity ?? ""] ?? 99;
        if (order < currentOrder) severity = val;
      }
    }

    // Affected products — ProductStatuses is a flat array; Type 3 = Known Affected
    const statuses = toArray(vuln.ProductStatuses);
    const affectedIds = new Set<string>();
    for (const s of statuses) {
      if (s.Type === 3) {
        for (const id of toArray(s.ProductID)) affectedIds.add(id);
      }
    }
    // Fallback: use product IDs from score sets
    if (affectedIds.size === 0) {
      for (const ss of scoreSets) {
        for (const id of toArray(ss.ProductID)) affectedIds.add(id);
      }
    }
    const affectedProducts = Array.from(affectedIds)
      .map((id) => productMap.get(id) ?? id)
      .filter((name) => !name.match(/^\d+$/))
      .slice(0, 15);

    // KB articles & patch URLs — Remediations is a flat array; Type 2 = Vendor Fix
    const remediations = toArray(vuln.Remediations);
    const kbArticles: string[] = [];
    const patchUrls: string[] = [];
    for (const rem of remediations) {
      if (rem.Type === 2 || rem.Type === 1) {
        const url = rem.URL ?? "";
        if (isSafeHttpUrl(url)) {
          patchUrls.push(url);
          const desc = strVal(rem.Description as { Value: string } | string | undefined);
          if (desc) kbArticles.push(desc);
        }
      }
    }

    // Derive attackVector from CVSS vector string
    let attackVector: string | null = null;
    if (cvssVector) {
      const avMatch = cvssVector.match(/AV:([^/]+)/);
      if (avMatch) {
        const avMap: Record<string, string> = { N: "Network", A: "Adjacent", L: "Local", P: "Physical" };
        attackVector = avMap[avMatch[1]] ?? avMatch[1];
      }
    }

    results.push({
      cveId,
      title,
      description,
      severity,
      cvssScore: isNaN(cvssScore ?? NaN) ? null : cvssScore,
      cvssVector,
      isExploited,
      isPubliclyDisclosed,
      affectedProducts,
      kbArticles: [...new Set(kbArticles)].slice(0, 5),
      patchUrls: [...new Set(patchUrls)].slice(0, 5),
      impactType,
      attackVector,
    });
  }

  // Sort: exploited first, then by severity, then CVSS
  const sevOrder: Record<string, number> = { Critical: 0, Important: 1, Moderate: 2, Low: 3 };
  results.sort((a, b) => {
    if (a.isExploited !== b.isExploited) return a.isExploited ? -1 : 1;
    if (a.isPubliclyDisclosed !== b.isPubliclyDisclosed) return a.isPubliclyDisclosed ? -1 : 1;
    const sa = sevOrder[a.severity ?? ""] ?? 4;
    const sb = sevOrder[b.severity ?? ""] ?? 4;
    if (sa !== sb) return sa - sb;
    return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
  });

  return results;
}

async function fetchDigest(releaseId: string): Promise<{
  releaseId: string; title: string; releaseDate: string;
  totalCves: number; critical: number; important: number; moderate: number; low: number;
  exploited: number; publiclyDisclosed: number; cves: PtCve[];
}> {
  const cacheKey = `pt_digest_${releaseId}`;
  const cached = getCache<ReturnType<typeof fetchDigest> extends Promise<infer T> ? T : never>(cacheKey);
  if (cached) return cached;

  try {
    logger.info({ releaseId }, "Fetching MSRC CVRF document");
    const res = await fetch(`${MSRC_BASE}/cvrf/${releaseId}`, {
      headers: { Accept: "application/json", "User-Agent": "CVE-Daily-Report/1.0" },
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) throw new Error(`MSRC CVRF fetch failed: ${res.status} for ${releaseId}`);

    const doc = (await res.json()) as CvrfDocument;

    // Build product ID → name map
    const productMap = new Map<string, string>();
    for (const p of toArray(doc.ProductTree?.FullProductName)) {
      productMap.set(p.ProductID, p.Value);
    }

    const cves = parseCvrf(doc, productMap);

    const title = strVal(doc.DocumentTitle) || releaseId;
    const releaseDate =
      doc.DocumentTracking?.InitialReleaseDate?.split("T")[0] ??
      doc.DocumentTracking?.CurrentReleaseDate?.split("T")[0] ??
      "";

    const digest = {
      releaseId,
      title,
      releaseDate,
      totalCves: cves.length,
      critical: cves.filter((c) => c.severity === "Critical").length,
      important: cves.filter((c) => c.severity === "Important").length,
      moderate: cves.filter((c) => c.severity === "Moderate").length,
      low: cves.filter((c) => c.severity === "Low").length,
      exploited: cves.filter((c) => c.isExploited).length,
      publiclyDisclosed: cves.filter((c) => c.isPubliclyDisclosed).length,
      cves,
    };

    setCache(cacheKey, digest, DIGEST_TTL);
    metrics.recordFetchSuccess("ptDigest");
    return digest;
  } catch (err) {
    metrics.recordFetchError("ptDigest", err);
    throw err;
  }
}

// ─── RSS / Known Issues ───────────────────────────────────────────────────────

interface PtIssue {
  id: string;
  title: string;
  url: string;
  source: string;
  sourceUrl: string;
  publishedDate: string;
  summary: string;
  category: string;
  affectedProducts: string[];
}

/** Simple inline RSS parser — handles CDATA and common quirks */
function extractTag(block: string, tag: string): string {
  // Try CDATA form first, then plain
  const cdataRe = new RegExp(`<${tag}[^>]*>\\s*<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>\\s*<\\/${tag}>`, "i");
  const plainRe  = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i");
  const m = cdataRe.exec(block) ?? plainRe.exec(block);
  return m ? m[1].trim() : "";
}

function stripHtml(html: string): string {
  return html
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#\d+;/g, "")
    .replace(/\s{2,}/g, " ")
    .trim();
}

/** Unified RSS 2.0 + Atom 1.0 parser (Reddit returns Atom) */
export function parseRssItems(xml: string) {
  const items: Array<{
    title: string; link: string; pubDate: string; description: string; categories: string[];
  }> = [];

  // Match both RSS <item> and Atom <entry> blocks
  const blockRe = /<(?:item|entry)[^>]*>([\s\S]*?)<\/(?:item|entry)>/gi;
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(xml)) !== null) {
    const block = m[1];
    const title = stripHtml(extractTag(block, "title"));

    // Link: RSS uses <link>text</link>; Atom uses <link href="URL" rel="alternate"/>
    let link = extractTag(block, "link");
    if (!link) {
      // Atom self-closing link with href attribute
      const hrefM = /<link[^>]+href="([^"]+)"[^>]*\/?>/i.exec(block);
      if (hrefM) link = hrefM[1];
    }
    if (!link) link = extractTag(block, "guid") || extractTag(block, "id");
    if (!isSafeHttpUrl(link)) link = "";

    // Date: RSS uses <pubDate>, Atom uses <updated> or <published>
    const pubDate = extractTag(block, "pubDate")
                 || extractTag(block, "published")
                 || extractTag(block, "updated")
                 || extractTag(block, "dc:date");

    // Body: RSS uses <description> or <content:encoded>; Atom uses <content> or <summary>
    const rawDesc = extractTag(block, "content:encoded")
                 || extractTag(block, "content")
                 || extractTag(block, "description")
                 || extractTag(block, "summary");
    const description = stripHtml(rawDesc);

    const categories: string[] = [];
    const catRe = /<category[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/category>/gi;
    let c: RegExpExecArray | null;
    while ((c = catRe.exec(block)) !== null) categories.push(c[1].trim());

    if (title && link) items.push({ title, link, pubDate, description, categories });
  }
  return items;
}

function simpleHash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) { h = Math.imul(31, h) + s.charCodeAt(i) | 0; }
  return Math.abs(h).toString(36);
}

const PRODUCT_RES = [
  /Windows 11(?:\s+\d+H\d+)?/i, /Windows 10(?:\s+\d+H\d+)?/i,
  /Windows Server\s+\d{4}(?:\s+R2)?/i, /Microsoft 365/i, /Office\s+\d{4}/i,
  /Exchange Server(?:\s+\d{4})?/i, /SharePoint(?:\s+Server)?/i,
  /SQL Server(?:\s+\d{4})?/i, /Microsoft Teams/i, /Microsoft Edge/i,
  /Outlook(?:\s+\d{4})?/i, /OneDrive/i, /Azure/i, /Microsoft Defender/i,
  /\.NET\s+(?:Framework\s+)?[\d.]+/i,
  // Common Patch Tuesday breakage targets
  /BitLocker/i, /Hyper-V/i, /Secure Boot/i, /TPM/i,
  /Remote Desktop/i, /RDP/i, /VPN/i, /print(?:er|ing)/i,
  /WSL/i, /Windows Subsystem/i, /Task Manager/i,
];

function extractAffectedProducts(text: string): string[] {
  const found = new Set<string>();
  for (const re of PRODUCT_RES) {
    const m = text.match(re);
    if (m) found.add(m[0].trim());
  }
  return Array.from(found).slice(0, 8);
}

const CATEGORY_RULES: Array<{ category: string; re: RegExp }> = [
  // BSOD / crash / boot — most critical, check first
  { category: "Bug",         re: /bsod|blue screen|boot loop|won.t boot|fails? to boot|restart loop|crash(?:ing|es)?|freeze|hang(?:ing)?|0x[0-9a-f]{6,}/i },
  { category: "Regression",  re: /regression|broke(?:n| after)?|breaking change|no longer work|stops? work(?:ing)?|fail(?:s|ed)? after|stop(?:ped)? after|issue after|problem after|after (?:the )?(?:update|patch|installing)/i },
  { category: "Workaround",  re: /workaround|mitigation|how to fix|how to resolve|temporary fix|rollback|uninstall.*update|remove.*patch/i },
  { category: "Advisory",    re: /advisory|warning|caution|do not install|recommend against|hold off|delay.*update|pause.*update/i },
  { category: "Analysis",    re: /analysis|summary|recap|review|overview|roundup|what.s new|what to expect/i },
];

export function classifyIssue(title: string, description: string): string {
  const text = title + " " + description;
  for (const { category, re } of CATEGORY_RULES) {
    if (re.test(text)) return category;
  }
  return "Discussion";
}

// ─── Sources: real-world issue reports after Patch Tuesday ───────────────────
// Reddit r/sysadmin    — IT pros report enterprise breakage in real time
// Reddit r/Windows10   — consumer Windows 10 issue reports
// Reddit r/Windows11   — consumer Windows 11 issue reports
// BleepingComputer     — trusted reporting on Windows update bugs
// Microsoft Tech Community IT Pro Blog — official known issues / advisories

// Keywords that indicate a post is about a real issue caused by a Windows update
const PT_ISSUE_RE =
  /patch tuesday|cumulative update|kb\d{5,7}|windows update|after (?:the )?(?:update|patch|installing)|bitlocker|bsod|blue screen|boot loop|won.t boot|restart loop|crash(?:ing)?|broke(?:n)? after|regression|known issue|issue after|problem after|update caus|patch caus|update broke|update break|rollback|uninstall.*update/i;

const SOURCES = [
  {
    name: "r/sysadmin",
    url: "https://www.reddit.com/r/sysadmin/new.rss",
    siteUrl: "https://www.reddit.com/r/sysadmin",
    // r/sysadmin: IT pros — tighter filter so only genuine post-patch reports come through
    keywords: /patch tuesday|cumulative update|kb\d{5,7}|windows update|bitlocker|bsod|blue screen|boot loop|won.t boot|after (?:the )?(?:update|patch)|update broke|update causing|regression|known issue/i,
  },
  {
    name: "r/Windows10",
    url: "https://www.reddit.com/r/Windows10/new.rss",
    siteUrl: "https://www.reddit.com/r/Windows10",
    keywords: PT_ISSUE_RE,
  },
  {
    name: "r/Windows11",
    url: "https://www.reddit.com/r/Windows11/new.rss",
    siteUrl: "https://www.reddit.com/r/Windows11",
    keywords: PT_ISSUE_RE,
  },
  {
    name: "BleepingComputer",
    url: "https://www.bleepingcomputer.com/feed/",
    siteUrl: "https://www.bleepingcomputer.com",
    keywords: /patch tuesday|cumulative update|known issue|windows update|microsoft update|kb\d{5,7}|windows.*(?:bug|regression|issue|crash|bsod)/i,
  },
  {
    name: "Microsoft Tech Community",
    url: "https://techcommunity.microsoft.com/t5/windows-it-pro-blog/bg-p/Windows10Blog/rss/board",
    siteUrl: "https://techcommunity.microsoft.com/t5/windows-it-pro-blog",
    keywords: /patch tuesday|cumulative update|known issue|update|security|advisory/i,
  },
];

interface PtIssuesResult {
  issues: PtIssue[];
  fetchedAt: string;
  windowStart: string;
  windowEnd: string;
  releaseId: string;
}

async function fetchKnownIssues(releaseId: string, releases: PtRelease[]): Promise<PtIssuesResult> {
  const cacheKey = `pt_issues_${releaseId}`;
  const cached = getCache<PtIssuesResult>(cacheKey);
  if (cached) return cached;

  const release = releases.find((r) => r.id === releaseId);
  if (!release) throw new Error(`Release ${releaseId} not found`);

  // Window: day before PT to 35 days after (covers the full inter-PT period)
  const ptDate = new Date(release.releaseDate);
  const windowStart = new Date(ptDate.getTime() - 24 * 60 * 60 * 1000);
  const windowEnd   = new Date(ptDate.getTime() + 35 * 24 * 60 * 60 * 1000);

  logger.info({ releaseId, windowStart, windowEnd }, "Fetching PT known issues from RSS");

  const allIssues: PtIssue[] = [];
  const seen = new Set<string>();

  for (const source of SOURCES) {
    try {
      const res = await fetch(source.url, {
        headers: { "User-Agent": "CVE-Daily-Report/1.0 (Patch Tuesday Issue Tracker)", Accept: "application/rss+xml, application/xml, text/xml" },
        signal: AbortSignal.timeout(15000),
      });
      if (!res.ok) {
        logger.warn({ source: source.name, status: res.status }, "RSS feed returned non-200");
        continue;
      }
      const xml = await res.text();
      const items = parseRssItems(xml);

      for (const item of items) {
        const pubDate = item.pubDate ? new Date(item.pubDate) : null;
        if (!pubDate || isNaN(pubDate.getTime())) continue;
        if (pubDate < windowStart || pubDate > windowEnd) continue;

        const text = item.title + " " + item.description;
        if (!source.keywords.test(text)) continue;

        const id = simpleHash(item.link);
        if (seen.has(id)) continue;
        seen.add(id);

        const summary = item.description.slice(0, 400) + (item.description.length > 400 ? "…" : "");
        const products = extractAffectedProducts(text);

        allIssues.push({
          id,
          title: item.title,
          url: item.link,
          source: source.name,
          sourceUrl: source.siteUrl,
          publishedDate: pubDate.toISOString().split("T")[0],
          summary,
          category: classifyIssue(item.title, item.description),
          affectedProducts: products,
        });
      }
    } catch (err) {
      logger.warn({ err, source: source.name }, "RSS source fetch failed — skipping");
    }
  }

  // Sort newest first
  allIssues.sort((a, b) => b.publishedDate.localeCompare(a.publishedDate));

  // Adaptive TTL: 30 min for the current month (still accumulating), 4 h for past months
  const isCurrentMonth = (() => {
    const now = new Date();
    return now >= windowStart && now <= windowEnd;
  })();
  const ttl = isCurrentMonth ? 30 * 60 * 1000 : 4 * 60 * 60 * 1000;

  const result: PtIssuesResult = {
    issues: allIssues,
    fetchedAt: new Date().toISOString(),
    windowStart: windowStart.toISOString().split("T")[0],
    windowEnd:   windowEnd.toISOString().split("T")[0],
    releaseId,
  };

  setCache(cacheKey, result, ttl);
  return result;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

router.get("/patch-tuesday/issues", async (req: Request, res: Response) => {
  try {
    const releases = await fetchReleases();
    const rawId = typeof req.query["releaseId"] === "string" ? req.query["releaseId"] : undefined;
    const releaseId = rawId || releases[0]?.id;
    if (!releaseId) {
      res.status(400).json({ error: "No releases available" });
      return;
    }
    const result = await fetchKnownIssues(releaseId, releases);
    res.json(result);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch PT known issues");
    res.status(502).json({ error: "Failed to fetch known issues" });
  }
});

router.get("/patch-tuesday/releases", async (_req: Request, res: Response) => {
  try {
    const releases = await fetchReleases();
    res.json(releases);
  } catch (err) {
    _req.log.error({ err }, "Failed to fetch PT releases");
    res.status(502).json({ error: "Failed to fetch Patch Tuesday releases" });
  }
});

router.get("/patch-tuesday", async (req: Request, res: Response) => {
  try {
    const { releaseId: requestedId } = GetPatchTuesdayDigestQueryParams.parse(req.query);

    let releaseId = requestedId;
    if (!releaseId) {
      const releases = await fetchReleases();
      releaseId = releases[0]?.id;
      if (!releaseId) throw new Error("No releases available");
    }

    const digest = await fetchDigest(releaseId);
    res.json(digest);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch PT digest");
    res.status(502).json({ error: "Failed to fetch Patch Tuesday data" });
  }
});

export default router;
