import { Router, type IRouter, type Request, type Response } from "express";
import {
  GetDailyCvesQueryParams,
  GetKevListQueryParams,
  GetCveByIdParams,
  GetCveChangesQueryParams,
  GetCvesSearchQueryParams,
  GetCvesTrendQueryParams,
} from "@workspace/api-zod";
import { logger } from "../lib/logger";
import { parseRequest } from "../lib/validation";
import { getEpssScores, applyEpss } from "../lib/epss";
import { getCveOrgRecords, applyCveOrg } from "../lib/cve-org";
import { getRedhatAdvisories, applyRedhatAdvisories } from "../lib/redhat";
import { parseSeverity } from "../lib/severity";
import { notifyAlerts, seedAlertBaseline } from "../lib/alerts";
import { isSafeHttpUrl } from "../lib/url-safety";
import * as metrics from "../lib/metrics";
import {
  loadCveSnapshots,
  saveCveSnapshots,
  loadRecentCveChanges,
  searchCveSnapshots,
  loadTrendBuckets,
} from "../lib/cve-store";

const router: IRouter = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

export type Platform = "Windows" | "macOS" | "Linux" | "iOS" | "Android" | "Network" | "Server" | "Cloud" | "Browser" | "Firmware" | "Other";
export type DeviceType = "Endpoint" | "Endpoint VM" | "Server" | "Network" | "Cloud" | "Mobile" | "Other";

export interface CveEntry {
  cveId: string;
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null;
  cvssScore: number | null;
  cvssVector: string | null;
  epssScore?: number | null;
  epssPercentile?: number | null;
  ssvcExploitation?: "none" | "poc" | "active" | null;
  ssvcAutomatable?: "yes" | "no" | null;
  ssvcTechnicalImpact?: "partial" | "total" | null;
  hasKnownPatch: boolean;
  isKnownExploited: boolean;
  affectedProducts: string[];
  patchUrls: string[];
  references: string[];
  vendor: string | null;
  cweIds: string[];
  platforms: Platform[];
  deviceType: DeviceType;
}

interface KevEntry {
  cveId: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null;
  cvssScore: number | null;
  patchable: boolean;
  platforms: Platform[];
  deviceType: DeviceType;
}

// ─── In-memory cache ─────────────────────────────────────────────────────────

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry<unknown>>();

function getCache<T>(key: string): T | null {
  const entry = cache.get(key);
  if (!entry || Date.now() > entry.expiresAt) {
    cache.delete(key);
    metrics.recordCacheMiss(key);
    return null;
  }
  metrics.recordCacheHit(key);
  return entry.data as T;
}

function setCache<T>(key: string, data: T, ttlMs: number): void {
  cache.set(key, { data, expiresAt: Date.now() + ttlMs });
}

const CVE_CACHE_TTL = 30 * 60 * 1000; // 30 minutes
const KEV_CACHE_TTL = 60 * 60 * 1000;        // 1 hour
const KEV_CVSS_CACHE_TTL = 6 * 60 * 60 * 1000; // 6 hours
const KEV_CVSS_RETRY_TTL = 5 * 60 * 1000; // a partial map shouldn't stick around for 6 hours

// An NVD_API key raises the rate limit from 1 req/6s to 50 req/30s.
const NVD_HEADERS: Record<string, string> = {
  "User-Agent": "CVE-Daily-Report/1.0",
  ...(process.env.NVD_API ? { apiKey: process.env.NVD_API } : {}),
};

// ─── KEV helpers ─────────────────────────────────────────────────────────────

/** True when requiredAction says to apply an update/patch (not merely mitigate/disconnect). */
function detectPatchable(requiredAction: string): boolean {
  const a = requiredAction.toLowerCase();
  return /apply (updates?|patches?|fix(es)?|the update|the patch)/.test(a)
    || /update (to |affected |impacted )?system/i.test(a)
    || /install (the |available |security )?update/i.test(a);
}

/** Simple vendor-text → platform mapping for KEV entries (no CPE strings available). */
const VENDOR_PLATFORM_MAP: Array<{ pattern: RegExp; platform: Platform }> = [
  { pattern: /\bmicrosoft\b/i,             platform: "Windows" },
  { pattern: /\bapple\b/i,                 platform: "macOS" },
  { pattern: /\bgoogle\b/i,                platform: "Android" },
  { pattern: /\blinux\b|\bredhat\b|\bcanonical\b|\bdebian\b|\bubuntu\b|\bsuse\b|\bfedora\b/i, platform: "Linux" },
  { pattern: /\bcisco\b|\bjuniper\b|\bfortinet\b|\bpalo alto\b|\bf5\b|\bsonicwall\b|\bnetgear\b|\bzyxel\b|\bd-?link\b|\btp-?link\b|\bubiquiti\b|\baruba\b/i, platform: "Network" },
  { pattern: /\bvmware\b|\bcitrix\b|\boracle\b|\bapache\b|\bnginx\b|\bibm\b|\bsap\b/i, platform: "Server" },
  { pattern: /\bamazon\b|\baws\b|\bazure\b|\bgcp\b|\bhashicorp\b/i, platform: "Cloud" },
  { pattern: /\bsiemens\b|\bschneider\b|\bhoneywell\b|\bge \b|\brockwell\b/i, platform: "Firmware" },
  { pattern: /\badobe\b|\bmozilla\b/i,      platform: "Other" },
];

function detectPlatformFromVendor(vendorProject: string, description: string): Platform[] {
  // Try vendor name first
  for (const { pattern, platform } of VENDOR_PLATFORM_MAP) {
    if (pattern.test(vendorProject)) return [platform];
  }
  // Fall back to description keyword scan
  for (const hint of DESC_PLATFORM_HINTS) {
    if (hint.keywords.test(description)) return [hint.platform];
  }
  return ["Other"];
}

/** Fetch CVSS scores for all KEV entries using NVD's hasKev param. Returns Map<cveId, {severity,cvssScore}>. */
async function fetchKevCvssMap(): Promise<Map<string, { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null; cvssScore: number | null }>> {
  const cached = getCache<Map<string, { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null; cvssScore: number | null }>>("kev_cvss_map");
  if (cached) return cached;

  logger.info("Fetching NVD CVSS data for KEV catalog");
  const map = new Map<string, { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null; cvssScore: number | null }>();

  let startIndex = 0;
  const pageSize = 2000;
  let totalResults = Infinity;
  let complete = true;

  while (startIndex < totalResults) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&resultsPerPage=${pageSize}&startIndex=${startIndex}`;
    try {
      const res = await fetch(url, { headers: NVD_HEADERS, signal: AbortSignal.timeout(60000) });
      if (!res.ok) {
        logger.warn({ status: res.status }, "NVD KEV CVSS fetch failed, skipping enrichment");
        complete = false;
        break;
      }
      const json = (await res.json()) as {
        totalResults: number;
        vulnerabilities: Array<{
          cve: {
            id: string;
            metrics?: {
              cvssMetricV31?: Array<{ cvssData?: { baseScore?: number } }>;
              cvssMetricV30?: Array<{ cvssData?: { baseScore?: number } }>;
              cvssMetricV2?: Array<{ cvssData?: { baseScore?: number } }>;
            };
          };
        }>;
      };
      totalResults = json.totalResults;
      for (const item of json.vulnerabilities) {
        const m = item.cve.metrics ?? {};
        const score =
          m.cvssMetricV31?.[0]?.cvssData?.baseScore ??
          m.cvssMetricV30?.[0]?.cvssData?.baseScore ??
          m.cvssMetricV2?.[0]?.cvssData?.baseScore ??
          null;
        map.set(item.cve.id, { severity: parseSeverity(score as number | null), cvssScore: score as number | null });
      }
      startIndex += pageSize;
      if (startIndex < totalResults) {
        await new Promise((r) => setTimeout(r, 700)); // respect NVD rate limit
      }
    } catch (err) {
      logger.warn({ err }, "NVD KEV CVSS fetch error, using partial data");
      complete = false;
      break;
    }
  }

  setCache("kev_cvss_map", map, complete ? KEV_CVSS_CACHE_TTL : KEV_CVSS_RETRY_TTL);
  return map;
}

// ─── Data fetchers ───────────────────────────────────────────────────────────

interface CisaKevFeed {
  vulnerabilities: Array<{
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    requiredAction: string;
    dueDate: string;
    knownRansomwareCampaignUse: string;
    notes?: string;
  }>;
}

// The timeout also covers reading the body, so the read has to happen here. Left until after the
// slower NVD lookup in loadKevCatalog, it would be aborted whenever NVD took over 15s.
async function fetchCisaKevFeed(): Promise<CisaKevFeed> {
  const res = await fetch(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    { signal: AbortSignal.timeout(15000) }
  );
  if (!res.ok) throw new Error(`KEV fetch failed: ${res.status}`);
  return (await res.json()) as CisaKevFeed;
}

// Every route needs this, so a cold start would otherwise send each parallel page request to NVD.
let kevFetchInFlight: Promise<Map<string, KevEntry>> | null = null;

async function fetchKevCatalog(): Promise<Map<string, KevEntry>> {
  const cached = getCache<Map<string, KevEntry>>("kev_map");
  if (cached) return cached;

  kevFetchInFlight ??= loadKevCatalog().finally(() => {
    kevFetchInFlight = null;
  });
  return kevFetchInFlight;
}

async function loadKevCatalog(): Promise<Map<string, KevEntry>> {
  try {
    logger.info("Fetching CISA KEV catalog");
    const [json, cvssMap] = await Promise.all([
      fetchCisaKevFeed(),
      fetchKevCvssMap().catch(() => new Map()),
    ]);

    const map = new Map<string, KevEntry>();
    for (const v of json.vulnerabilities) {
      const nvd = cvssMap.get(v.cveID);
      map.set(v.cveID, {
        cveId: v.cveID,
        vendorProject: v.vendorProject,
        product: v.product,
        vulnerabilityName: v.vulnerabilityName,
        dateAdded: v.dateAdded,
        shortDescription: v.shortDescription,
        requiredAction: v.requiredAction,
        dueDate: v.dueDate,
        knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
        notes: v.notes ?? null,
        severity: nvd?.severity ?? null,
        cvssScore: nvd?.cvssScore ?? null,
        patchable: detectPatchable(v.requiredAction),
        platforms: detectPlatformFromVendor(v.vendorProject, v.shortDescription),
        deviceType: detectDeviceTypeFromVendor(v.vendorProject, v.product, v.shortDescription),
      });
    }

    setCache("kev_map", map, KEV_CACHE_TTL);
    metrics.recordFetchSuccess("kev");
    return map;
  } catch (err) {
    metrics.recordFetchError("kev", err);
    throw err;
  }
}

// ─── Platform detection ───────────────────────────────────────────────────────

// CPE vendor/product → platform mapping rules (checked in order)
const CPE_PLATFORM_RULES: Array<{ patterns: RegExp[]; platform: Platform }> = [
  // Windows
  { patterns: [/^microsoft\/(windows|win32|win64|windows_server|windows_10|windows_11|windows_xp|windows_vista|windows_7|windows_8|windows_rt)/i], platform: "Windows" },
  // macOS
  { patterns: [/^apple\/(macos|mac_os_x|macos_monterey|macos_ventura|macos_sonoma|macos_sequoia)/i], platform: "macOS" },
  // iOS
  { patterns: [/^apple\/(iphone_os|ipados|ios)/i], platform: "iOS" },
  // Android
  { patterns: [/^google\/android/i, /^android/i], platform: "Android" },
  // Network devices
  {
    patterns: [
      /^cisco\//i, /^juniper\//i, /^fortinet\//i, /^palo_alto_networks\//i,
      /^f5\//i, /^checkpoint\//i, /^sonicwall\//i, /^netgear\//i,
      /^zyxel\//i, /^dlink\//i, /^tp-link\//i, /^ubiquiti\//i,
      /^aruba\//i, /^extreme_networks\//i, /^barracuda\//i,
      /\/(router|firewall|switch|vpn|ids|ips|utm)/i,
    ],
    platform: "Network",
  },
  // Cloud
  {
    patterns: [
      /^amazon\/(aws|ec2|s3|lambda|rds|eks|ecs)/i,
      /^microsoft\/(azure|office_365|sharepoint_online|teams)/i,
      /^google\/(cloud|kubernetes_engine|gke|gcp)/i,
      /^hashicorp\//i, /^terraform\//i,
    ],
    platform: "Cloud",
  },
  // Browser
  {
    patterns: [
      /^google\/chrome/i, /^mozilla\/firefox/i, /^apple\/safari/i,
      /^microsoft\/edge/i, /^opera\//i, /^brave\//i,
    ],
    platform: "Browser",
  },
  // Linux
  {
    patterns: [
      /^linux\/(linux_kernel|kernel)/i, /^redhat\//i, /^canonical\//i,
      /^debian\//i, /^ubuntu\//i, /^suse\//i, /^fedora\//i,
      /^centos\//i, /^almalinux\//i, /^rockylinux\//i, /^arch_linux\//i,
      /^gentoo\//i, /^alpine_linux\//i,
    ],
    platform: "Linux",
  },
  // Server software
  {
    patterns: [
      /^apache\//i, /^nginx\//i, /^microsoft\/iis/i,
      /^microsoft\/(sql_server|exchange_server|sharepoint_server)/i,
      /^oracle\/(database|mysql|weblogic)/i, /^ibm\/(websphere|db2)/i,
      /^vmware\//i, /^citrix\//i, /^openssl\//i,
      /\/(server|daemon|service|backend)/i,
    ],
    platform: "Server",
  },
  // Firmware / embedded
  {
    patterns: [
      /^siemens\//i, /^schneider_electric\//i, /^honeywell\//i,
      /^ge\//i, /^rockwell_automation\//i, /\/(firmware|bios|uefi|bootloader|embedded)/i,
    ],
    platform: "Firmware",
  },
];

// Description keyword hints (fallback when CPE data is absent)
const DESC_PLATFORM_HINTS: Array<{ keywords: RegExp; platform: Platform }> = [
  { keywords: /\bwindows\b/i, platform: "Windows" },
  { keywords: /\bmacos\b|\bmac os\b|\bos x\b/i, platform: "macOS" },
  { keywords: /\blinux\b|\bkernel\b/i, platform: "Linux" },
  { keywords: /\bios\b|\biphone\b|\bipad\b/i, platform: "iOS" },
  { keywords: /\bandroid\b/i, platform: "Android" },
  { keywords: /\brouter\b|\bfirewall\b|\bswitch\b|\bvpn\b|\bnetwork device\b/i, platform: "Network" },
  { keywords: /\baws\b|\bazure\b|\bgcp\b|\bcloud\b/i, platform: "Cloud" },
  { keywords: /\bchrome\b|\bfirefox\b|\bsafari\b|\bbrowser\b/i, platform: "Browser" },
  { keywords: /\bfirmware\b|\bbios\b|\buefi\b|\bembedded\b/i, platform: "Firmware" },
  { keywords: /\bserver\b|\bdatabase\b|\bweb server\b/i, platform: "Server" },
];

export function detectPlatforms(cpeStrings: string[], description: string): Platform[] {
  const found = new Set<Platform>();

  for (const cpe of cpeStrings) {
    // CPE format: cpe:2.3:type:vendor:product:...
    const parts = cpe.split(":");
    if (parts.length < 5) continue;
    const vendorProduct = `${parts[3]}/${parts[4]}`;

    for (const rule of CPE_PLATFORM_RULES) {
      if (rule.patterns.some((p) => p.test(vendorProduct))) {
        found.add(rule.platform);
        break;
      }
    }
  }

  // Fallback: scan description text when CPE data is absent or sparse
  if (found.size === 0) {
    for (const hint of DESC_PLATFORM_HINTS) {
      if (hint.keywords.test(description)) {
        found.add(hint.platform);
      }
    }
  }

  return found.size > 0 ? Array.from(found) : ["Other"];
}

// ─── Device type ──────────────────────────────────────────────────────────────

const CPE_DEVICE_TYPE_RULES: Array<{ patterns: RegExp[]; deviceType: DeviceType }> = [
  // Endpoint VM — check before Endpoint/Server so workstation/fusion don't fall through to "Windows"
  {
    patterns: [
      /^vmware\/(workstation|fusion|player)/i,
      /^oracle\/virtualbox/i, /^innotek\/virtualbox/i,
      /^parallels\/parallels_desktop/i,
    ],
    deviceType: "Endpoint VM",
  },
  // Mobile
  {
    patterns: [/^apple\/(iphone_os|ipados|ios)/i, /^google\/android/i],
    deviceType: "Mobile",
  },
  // Endpoint (client OS + desktop apps including browsers)
  {
    patterns: [
      /^microsoft\/(windows_10|windows_11|windows_8|windows_7|windows_vista|windows_xp|windows_rt)/i,
      /^apple\/(macos|mac_os_x|macos_monterey|macos_ventura|macos_sonoma|macos_sequoia)/i,
      /^microsoft\/(office|excel|word|powerpoint|outlook|onenote|access|publisher|visio|project)/i,
      /^adobe\/(acrobat|reader|flash_player|shockwave_player|photoshop|illustrator)/i,
      /^google\/(chrome|chrome_os)/i, /^mozilla\/firefox/i,
      /^microsoft\/edge/i, /^apple\/safari/i, /^opera\//i,
    ],
    deviceType: "Endpoint",
  },
  // Network devices
  {
    patterns: [
      /^cisco\//i, /^juniper\//i, /^fortinet\//i, /^palo_alto_networks\//i,
      /^f5\//i, /^checkpoint\//i, /^sonicwall\//i, /^netgear\//i,
      /^zyxel\//i, /^dlink\//i, /^tp-link\//i, /^ubiquiti\//i, /^aruba\//i,
    ],
    deviceType: "Network",
  },
  // Cloud
  {
    patterns: [
      /^amazon\/(aws|ec2|s3|lambda|rds|eks)/i,
      /^microsoft\/(azure|office_365|sharepoint_online|teams)/i,
      /^google\/(cloud|kubernetes_engine|gke)/i,
    ],
    deviceType: "Cloud",
  },
  // Server (OS, server software, hypervisors)
  {
    patterns: [
      /^microsoft\/windows_server/i,
      /^linux\/(linux_kernel|kernel)/i,
      /^redhat\//i, /^canonical\//i, /^debian\//i, /^ubuntu\//i, /^suse\//i, /^fedora\//i, /^centos\//i,
      /^apache\//i, /^nginx\//i,
      /^microsoft\/(iis|sql_server|exchange_server|sharepoint_server|hyper-v)/i,
      /^oracle\/(database|mysql|weblogic)/i, /^ibm\/(websphere|db2)/i,
      /^vmware\/(esxi|vsphere|vcenter)/i, /^citrix\//i, /^openssl\//i,
    ],
    deviceType: "Server",
  },
];

const DESC_DEVICE_TYPE_HINTS: Array<{ keywords: RegExp; deviceType: DeviceType }> = [
  { keywords: /vmware workstation|virtualbox|parallels desktop|vmware fusion/i, deviceType: "Endpoint VM" },
  { keywords: /\biphone\b|\bipad\b|\bipados\b|\bandroid\b/i, deviceType: "Mobile" },
  { keywords: /windows (10|11|8\.1|8|7|vista|xp)\b|laptop|desktop|workstation|\bmacos\b|\bmac os\b/i, deviceType: "Endpoint" },
  { keywords: /windows server|linux kernel|\bubuntu\b|\bdebian\b|\bcentos\b|\bred hat\b|exchange server|sql server|\bnginx\b|\bapache\b/i, deviceType: "Server" },
  { keywords: /\brouter\b|\bfirewall\b|\bswitch\b|\bnetwork device\b/i, deviceType: "Network" },
  { keywords: /\baws\b|\bazure\b|\bgcp\b|\bcloud\b/i, deviceType: "Cloud" },
];

export function detectDeviceType(cpeStrings: string[], description: string): DeviceType {
  for (const cpe of cpeStrings) {
    const parts = cpe.split(":");
    if (parts.length < 5) continue;
    const vendorProduct = `${parts[3]}/${parts[4]}`;
    for (const rule of CPE_DEVICE_TYPE_RULES) {
      if (rule.patterns.some((p) => p.test(vendorProduct))) return rule.deviceType;
    }
  }
  for (const hint of DESC_DEVICE_TYPE_HINTS) {
    if (hint.keywords.test(description)) return hint.deviceType;
  }
  return "Other";
}

/** Derive device type for KEV entries (no CPE strings, use vendorProject + product text). */
const VENDOR_DEVICE_TYPE_MAP: Array<{ pattern: RegExp; deviceType: DeviceType }> = [
  { pattern: /vmware workstation|vmware fusion|virtualbox|parallels desktop/i, deviceType: "Endpoint VM" },
  { pattern: /\biphone\b|\bipad\b|\bios\b|\bandroid\b/i,                       deviceType: "Mobile" },
  { pattern: /\bapple\b/i,                                                      deviceType: "Endpoint" },
  { pattern: /\bgoogle\b.*\bchrome\b|\bchromium\b/i,                            deviceType: "Endpoint" },
  { pattern: /\bgoogle\b.*\bandroid\b/i,                                        deviceType: "Mobile" },
  { pattern: /\bgoogle\b/i,                                                     deviceType: "Mobile" },
  { pattern: /\bcisco\b|\bjuniper\b|\bfortinet\b|\bpalo alto\b|\bf5\b|\bsonicwall\b|\bnetgear\b|\bzyxel\b|\bd-?link\b|\btp-?link\b|\bubiquiti\b|\baruba\b/i, deviceType: "Network" },
  { pattern: /\bamazon\b|\baws\b|\bazure\b|\bgcp\b/i,                            deviceType: "Cloud" },
  { pattern: /\bvmware\b/i,                                                     deviceType: "Server" },
  { pattern: /\blinux\b|\bredhat\b|\bcanonical\b|\bdebian\b|\bubuntu\b|\bsuse\b|\bfedora\b/i, deviceType: "Server" },
];

function detectDeviceTypeFromVendor(vendorProject: string, product: string, description: string): DeviceType {
  const combined = `${vendorProject} ${product}`;
  for (const { pattern, deviceType } of VENDOR_DEVICE_TYPE_MAP) {
    if (pattern.test(combined)) return deviceType;
  }
  // Microsoft: distinguish client OS vs server OS vs desktop apps
  if (/\bmicrosoft\b/i.test(vendorProject)) {
    if (/windows server/i.test(combined)) return "Server";
    if (/windows (10|11|8|7|vista|xp|rt)\b|windows client/i.test(combined)) return "Endpoint";
    if (/exchange|sql server|sharepoint server|hyper-v|iis|biztalk|system center/i.test(combined)) return "Server";
    if (/azure|office 365|teams.*online|sharepoint online/i.test(combined)) return "Cloud";
    // Default Microsoft → Endpoint (Office, Edge, etc.)
    return "Endpoint";
  }
  // Description fallback
  for (const hint of DESC_DEVICE_TYPE_HINTS) {
    if (hint.keywords.test(description)) return hint.deviceType;
  }
  return "Other";
}

// CNAs often fill the vendor field with a placeholder when they have nothing better.
const PLACEHOLDER_VENDOR = /^(n\/?a|unknown|unspecified)$/i;

function extractFromNvdItem(
  item: NvdCveItem,
  kevMap: Map<string, KevEntry>
): CveEntry {
  const cve = item.cve;
  const cveId = cve.id;

  const description =
    cve.descriptions?.find((d: { lang: string; value: string }) => d.lang === "en")
      ?.value ?? "No description available.";

  // CVSS v3.1 preferred, then v3.0, v4.0 (many CNAs now publish only v4), then v2
  let cvssScore: number | null = null;
  let cvssVector: string | null = null;

  const metrics = cve.metrics ?? {};
  const v31 = metrics.cvssMetricV31?.[0];
  const v30 = metrics.cvssMetricV30?.[0];
  const v40 = metrics.cvssMetricV40?.[0];
  const v2 = metrics.cvssMetricV2?.[0];

  if (v31) {
    cvssScore = v31.cvssData?.baseScore ?? null;
    cvssVector = v31.cvssData?.vectorString ?? null;
  } else if (v30) {
    cvssScore = v30.cvssData?.baseScore ?? null;
    cvssVector = v30.cvssData?.vectorString ?? null;
  } else if (v40) {
    cvssScore = v40.cvssData?.baseScore ?? null;
    cvssVector = v40.cvssData?.vectorString ?? null;
  } else if (v2) {
    cvssScore = v2.cvssData?.baseScore ?? null;
    cvssVector = v2.cvssData?.vectorString ?? null;
  }

  const severity = parseSeverity(cvssScore);

  // References — detect patch/advisory URLs
  const references: string[] = [];
  const patchUrls: string[] = [];
  const seenReferenceUrls = new Set<string>();
  const patchKeywords = ["patch", "fix", "advisory", "update", "bulletin", "release", "security"];

  for (const ref of cve.references ?? []) {
    if (!isSafeHttpUrl(ref.url) || seenReferenceUrls.has(ref.url)) continue;
    seenReferenceUrls.add(ref.url);
    references.push(ref.url);
    const tags: string[] = ref.tags ?? [];
    const urlLower = ref.url.toLowerCase();
    if (
      tags.some((t: string) => t.toLowerCase().includes("patch")) ||
      tags.some((t: string) => t.toLowerCase().includes("vendor advisory")) ||
      patchKeywords.some((kw) => urlLower.includes(kw))
    ) {
      patchUrls.push(ref.url);
    }
  }

  const hasKnownPatch = patchUrls.length > 0;

  // Affected products + CPE strings from configurations
  const affectedProducts: string[] = [];
  const cpeStrings: string[] = [];
  const seenProducts = new Set<string>();
  for (const node of cve.configurations?.flatMap(
    (c: { nodes: NvdNode[] }) => c.nodes
  ) ?? []) {
    for (const match of node.cpeMatch ?? []) {
      if (match.criteria) cpeStrings.push(match.criteria);
      const parts = match.criteria?.split(":") ?? [];
      if (parts.length >= 5) {
        const vendor = parts[3];
        const product = parts[4];
        const label = `${vendor}/${product}`;
        if (!seenProducts.has(label)) {
          seenProducts.add(label);
          affectedProducts.push(label);
        }
      }
    }
  }

  // Fall back to the CNA-supplied `affected` block when NVD hasn't published
  // CPE configurations for this CVE yet (common while "Undergoing Analysis").
  if (affectedProducts.length === 0) {
    for (const item of cve.affected ?? []) {
      for (const data of item.affectedData ?? []) {
        if (!data.vendor || !data.product || PLACEHOLDER_VENDOR.test(data.vendor)) continue;
        const label = `${data.vendor}/${data.product}`;
        if (!seenProducts.has(label)) {
          seenProducts.add(label);
          affectedProducts.push(label);
        }
      }
    }
  }

  const vendor = affectedProducts.length > 0
    ? affectedProducts[0].split("/")[0]
    : null;

  const platforms = detectPlatforms(cpeStrings, description);
  const deviceType = detectDeviceType(cpeStrings, description);

  const cweIds: string[] = [];
  for (const weakness of cve.weaknesses ?? []) {
    for (const desc of weakness.description ?? []) {
      if (desc.value && desc.value !== "NVD-CWE-Other" && desc.value !== "NVD-CWE-noinfo") {
        cweIds.push(desc.value);
      }
    }
  }

  return {
    cveId,
    description,
    publishedDate: cve.published,
    lastModifiedDate: cve.lastModified,
    severity,
    cvssScore,
    cvssVector,
    hasKnownPatch,
    isKnownExploited: kevMap.has(cveId),
    affectedProducts: affectedProducts.slice(0, 10),
    patchUrls: patchUrls.slice(0, 5),
    references: references.slice(0, 10),
    vendor,
    cweIds,
    platforms,
    deviceType,
  };
}

interface NvdNode {
  cpeMatch?: Array<{ criteria?: string }>;
}

interface NvdCveItem {
  cve: {
    id: string;
    published: string;
    lastModified: string;
    vulnStatus?: string;
    descriptions?: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{ cvssData?: { baseScore: number; vectorString: string } }>;
      cvssMetricV30?: Array<{ cvssData?: { baseScore: number; vectorString: string } }>;
      cvssMetricV40?: Array<{ cvssData?: { baseScore: number; vectorString: string } }>;
      cvssMetricV2?: Array<{ cvssData?: { baseScore: number; vectorString: string } }>;
    };
    references?: Array<{ url: string; tags?: string[] }>;
    configurations?: Array<{ nodes: NvdNode[] }>;
    weaknesses?: Array<{ description?: Array<{ value: string }> }>;
    // CNA-supplied structured vendor/product data — present on CVE-record-v5
    // style entries (common while a CVE is still "Undergoing Analysis" and
    // NVD hasn't published CPE `configurations` for it yet).
    affected?: Array<{
      affectedData?: Array<{ vendor?: string; product?: string }>;
    }>;
  };
}

// Daily is a strict subset of weekly's 7-day window (same NVD fields, same
// KEV cross-referencing), so it's derived from the already-fetched/warmed/
// persisted weekly dataset instead of issuing its own separate NVD call —
// that also means it's never left uncached after a restart or TTL expiry
// the way its own independent live fetch would be.
async function fetchDailyCves(kevMap: Map<string, KevEntry>): Promise<CveEntry[]> {
  const cacheKey = "daily_cves";
  const cached = getCache<CveEntry[]>(cacheKey);
  if (cached) return cached;

  try {
    const weekly = await fetchWeeklyCves(kevMap);
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    const entries = weekly.filter((c) => new Date(c.publishedDate).getTime() >= cutoff);

    setCache(cacheKey, entries, CVE_CACHE_TTL);
    metrics.recordFetchSuccess("daily");
    return entries;
  } catch (err) {
    metrics.recordFetchError("daily", err);
    throw err;
  }
}

// ─── Weekly fetch (7 days) ───────────────────────────────────────────────────

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_PAGE_SIZE = 2000; // NVD's maximum; a typical week is ~3,500 CVEs
const NVD_MAX_PAGES = 5;
const NVD_PUBLIC_GAP_MS = 6000; // the public (no-key) limit
const OLDER_UPDATES_WINDOW_MS = 24 * 60 * 60 * 1000;
const STALE_RETRY_TTL = 5 * 60 * 1000;

let lastGoodWeekly: CveEntry[] | null = null;
let nextNvdSlot = 0;

/** Holds the caller until its turn under the public rate limit. No-op with an API key. */
async function paceNvd(): Promise<void> {
  if (process.env.NVD_API) return;
  const now = Date.now();
  const slot = Math.max(now, nextNvdSlot);
  nextNvdSlot = slot + NVD_PUBLIC_GAP_MS;
  if (slot > now) await new Promise((r) => setTimeout(r, slot - now));
}

/** Runs one NVD query through every page. Throws if any page fails, so callers never get a partial list. */
async function fetchNvdEntries(
  params: Record<string, string>,
  kevMap: Map<string, KevEntry>,
): Promise<CveEntry[]> {
  const entries: CveEntry[] = [];
  let totalResults = Infinity;

  for (let page = 0; page * NVD_PAGE_SIZE < totalResults; page++) {
    if (page === NVD_MAX_PAGES) {
      logger.warn({ totalResults, fetched: entries.length }, "NVD query exceeded the page limit; results truncated");
      break;
    }
    const url = new URL(NVD_URL);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    url.searchParams.set("resultsPerPage", String(NVD_PAGE_SIZE));
    url.searchParams.set("startIndex", String(page * NVD_PAGE_SIZE));

    await paceNvd();
    // NVD treats these as bare flags, and URLSearchParams would add a trailing "=".
    const res = await fetch(url.toString().replace("hasKev=&", "hasKev&"), {
      headers: NVD_HEADERS,
      signal: AbortSignal.timeout(90000), // a full page takes NVD ~30s
    });
    if (!res.ok) throw new Error(`NVD fetch failed: ${res.status}`);

    const json = (await res.json()) as { totalResults?: number; vulnerabilities?: NvdCveItem[] };
    totalResults = json.totalResults ?? 0;
    for (const item of json.vulnerabilities ?? []) {
      if (item.cve.vulnStatus !== "Rejected") entries.push(extractFromNvdItem(item, kevMap));
    }
  }
  return entries;
}

function dedupeByCveId(entries: CveEntry[]): CveEntry[] {
  return [...new Map(entries.map((e) => [e.cveId, e])).values()];
}

/**
 * CVEs published before the 7-day window that changed recently: late NVD scores, and older CVEs
 * newly added to KEV. They aren't part of the weekly list, but they keep Postgres current and feed
 * alerts. Best-effort, because the weekly list is still complete without them.
 */
async function fetchOlderUpdates(kevMap: Map<string, KevEntry>, now: Date, weekAgo: Date): Promise<CveEntry[]> {
  const nvdDate = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, ".000");
  const queries: Array<Record<string, string>> = [
    { hasKev: "", kevStartDate: nvdDate(weekAgo), kevEndDate: nvdDate(now) },
    {
      lastModStartDate: nvdDate(new Date(now.getTime() - OLDER_UPDATES_WINDOW_MS)),
      lastModEndDate: nvdDate(now),
    },
  ];

  const found: CveEntry[] = [];
  for (const params of queries) {
    try {
      found.push(...(await fetchNvdEntries(params, kevMap)));
    } catch (err) {
      logger.warn({ err }, "NVD older-updates fetch failed; continuing without them");
    }
  }
  return dedupeByCveId(found).filter((e) => new Date(e.publishedDate) < weekAgo);
}

const ENRICHMENT_RANK: Record<string, number> = { CRITICAL: 1, HIGH: 2, MEDIUM: 4, LOW: 5 };

/** Lookup order for capped enrichment: what matters most gets its SSVC data first. */
function enrichmentRank(e: CveEntry): number {
  if (e.isKnownExploited) return 0;
  return ENRICHMENT_RANK[e.severity ?? ""] ?? 3;
}

/** Adds CVE.org, Red Hat and EPSS data. Each source is best-effort and none of them throw. */
async function enrichEntries(entries: CveEntry[]): Promise<CveEntry[]> {
  const prioritised = [...entries].sort((a, b) => enrichmentRank(a) - enrichmentRank(b));
  const withCveOrg = applyCveOrg(entries, await getCveOrgRecords(prioritised.map((e) => e.cveId)));

  const unpatched = withCveOrg.filter((e) => !e.hasKnownPatch).map((e) => e.cveId);
  const withFixes = applyRedhatAdvisories(withCveOrg, await getRedhatAdvisories(unpatched));

  return applyEpss(withFixes, await getEpssScores(withFixes.map((e) => e.cveId)));
}

// Deduplicate concurrent fetches: if a fetch is already in-flight,
// all callers await the same promise instead of starting duplicate requests.
let weeklyFetchInFlight: Promise<CveEntry[]> | null = null;

async function fetchWeeklyCves(kevMap: Map<string, KevEntry>, opts?: { force?: boolean }): Promise<CveEntry[]> {
  const cacheKey = "weekly_cves";
  if (!opts?.force) {
    const cached = getCache<CveEntry[]>(cacheKey);
    if (cached) return cached;
  }

  if (weeklyFetchInFlight) {
    logger.info("Weekly CVE fetch already in-flight, waiting…");
    return weeklyFetchInFlight;
  }

  const doFetch = async (): Promise<CveEntry[]> => {
    try {
      const now = new Date();
      const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const pubStartDate = weekAgo.toISOString().replace(/\.\d{3}Z$/, ".000");
      const pubEndDate = now.toISOString().replace(/\.\d{3}Z$/, ".000");

      logger.info({ pubStartDate, pubEndDate }, "Fetching NVD weekly CVEs");

      const weekly = dedupeByCveId(await fetchNvdEntries({ pubStartDate, pubEndDate }, kevMap));
      const weeklyIds = new Set(weekly.map((e) => e.cveId));
      const older = (await fetchOlderUpdates(kevMap, now, weekAgo)).filter((e) => !weeklyIds.has(e.cveId));

      // Order is preserved, so the weekly entries stay at the front.
      const all = await enrichEntries([...weekly, ...older]);
      const enriched = all.slice(0, weekly.length);

      setCache(cacheKey, enriched, 60 * 60 * 1000); // 1-hour TTL
      cache.delete("daily_cves"); // derived from weekly, so it's now out of date
      lastGoodWeekly = enriched;
      metrics.recordFetchSuccess("weekly");

      // Best-effort persistence — never let a slow/unavailable Postgres delay
      // the response that triggered this fetch.
      void saveCveSnapshots(all);
      void notifyAlerts(all);

      return enriched;
    } catch (err) {
      metrics.recordFetchError("weekly", err);
      // A partial list would look like a quiet week, so keep serving the last complete one.
      if (lastGoodWeekly) {
        logger.warn({ err }, "Weekly CVE fetch failed; serving the last complete dataset");
        setCache(cacheKey, lastGoodWeekly, STALE_RETRY_TTL);
        return lastGoodWeekly;
      }
      throw err;
    }
  };

  weeklyFetchInFlight = doFetch().finally(() => {
    weeklyFetchInFlight = null;
  });

  return weeklyFetchInFlight;
}

/**
 * Live NVD refresh + Postgres persistence (fetchWeeklyCves already persists
 * internally). Called once at startup and on a recurring interval — see
 * index.ts — so the cache is proactively kept warm instead of only
 * refreshing reactively whenever a request happens to hit an expired one.
 *
 * Always forces a real fetch: at startup this runs right after the
 * Postgres-snapshot warm-up sets "weekly_cves" with a fresh TTL, so an
 * unforced call would just hit that entry and return immediately without
 * ever actually refreshing — silently leaving Postgres stuck on whatever
 * was last fetched, indefinitely, across restarts.
 */
export async function refreshCveCache(): Promise<void> {
  try {
    logger.info("Refreshing weekly CVE cache from NVD");
    const kevMap = await fetchKevCatalog();
    await fetchWeeklyCves(kevMap, { force: true });
    logger.info("Weekly CVE cache refreshed");
  } catch (err) {
    logger.warn({ err }, "Background weekly cache refresh failed (will retry on next request or interval)");
  }
}

/** One-time cold-start warmup — call after server starts. */
export async function warmWeeklyCache(): Promise<void> {
  // If Postgres has a snapshot from a previous run, warm the cache from it
  // immediately so the first request after a cold start doesn't wait on NVD.
  const snapshot = await loadCveSnapshots();
  if (snapshot && snapshot.length > 0) {
    // The table keeps every CVE ever seen, but the cache only holds the 7-day window.
    const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const inWindow = snapshot.filter((c) => new Date(c.publishedDate).getTime() >= weekAgo);
    // EPSS isn't persisted. It's quick to fetch, so don't leave it blank until the much slower
    // full refresh finishes. The scores stay cached, so that refresh reuses them.
    const recent = applyEpss(inWindow, await getEpssScores(inWindow.map((c) => c.cveId)));
    setCache("weekly_cves", recent, 60 * 60 * 1000);
    lastGoodWeekly = recent;
    logger.info({ count: recent.length }, "Warmed weekly CVE cache from Postgres snapshot");
    // Anything already in the last persisted snapshot was present before this restart —
    // don't re-alert it, but do alert anything that appeared while we were down.
    seedAlertBaseline(snapshot);
  }

  await refreshCveCache();
}

// ─── Routes ───────────────────────────────────────────────────────────────────

router.get("/cves/weekly", async (req: Request, res: Response) => {
  try {
    const query = parseRequest(GetDailyCvesQueryParams, req.query, req, res);
    if (!query) return;
    const kevMap = await fetchKevCatalog();
    let cves = await fetchWeeklyCves(kevMap);

    if (query.severity) {
      cves = cves.filter((c) => c.severity === query.severity);
    }
    if (query.patchedOnly) {
      cves = cves.filter((c) => c.hasKnownPatch);
    }

    // patched first, then by severity, then CVSS desc
    const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    cves = [...cves].sort((a, b) => {
      if (a.hasKnownPatch !== b.hasKnownPatch) return a.hasKnownPatch ? -1 : 1;
      const sa = sevOrder[a.severity ?? ""] ?? 4;
      const sb = sevOrder[b.severity ?? ""] ?? 4;
      if (sa !== sb) return sa - sb;
      return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
    });

    res.json(cves);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch weekly CVEs");
    res.status(502).json({ error: "Failed to fetch CVE data from NVD" });
  }
});

router.get("/cves/daily", async (req: Request, res: Response) => {
  try {
    const query = parseRequest(GetDailyCvesQueryParams, req.query, req, res);
    if (!query) return;
    const kevMap = await fetchKevCatalog();
    let cves = await fetchDailyCves(kevMap);

    if (query.severity) {
      cves = cves.filter((c) => c.severity === query.severity);
    }
    if (query.patchedOnly) {
      cves = cves.filter((c) => c.hasKnownPatch);
    }

    res.json(cves);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch daily CVEs");
    res.status(502).json({ error: "Failed to fetch CVE data from NVD" });
  }
});

router.get("/cves/kev", async (req: Request, res: Response) => {
  try {
    if (!parseRequest(GetKevListQueryParams, req.query, req, res)) return;
    const kevMap = await fetchKevCatalog();
    const entries = Array.from(kevMap.values())
      .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
    res.json(entries);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch KEV list");
    res.status(502).json({ error: "Failed to fetch CISA KEV data" });
  }
});

router.get("/cves/changes", async (req: Request, res: Response) => {
  try {
    const query = parseRequest(GetCveChangesQueryParams, req.query, req, res);
    if (!query) return;
    const rows = await loadRecentCveChanges({
      limit: query.limit,
      field: query.field,
      cveId: query.cveId,
      offset: query.offset,
    });
    const changes = rows.map((row) => ({
      cveId: row.cveId,
      field: row.field,
      oldValue: row.oldValue,
      newValue: row.newValue,
      changedAt: row.changedAt.toISOString(),
    }));
    res.json(changes);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch CVE change history");
    res.status(502).json({ error: "Failed to fetch CVE change history" });
  }
});

router.get("/cves/search", async (req: Request, res: Response) => {
  try {
    const query = parseRequest(GetCvesSearchQueryParams, req.query, req, res);
    if (!query) return;
    const { q, cwe, severity, exploited, minEpss } = query;
    if (!q && !cwe && !severity && !exploited && minEpss === undefined) {
      res.status(400).json({ error: "Provide q or at least one filter" });
      return;
    }
    const limit = query.limit ?? 25;

    // EPSS isn't persisted, so minEpss can only be answered from the in-memory weekly data.
    const dbResults = minEpss === undefined
      ? await searchCveSnapshots({ q, cwe, severity, exploited }, limit)
      : null;

    if (dbResults !== null) {
      res.json(dbResults);
      return;
    }

    // No persistent store configured — fall back to filtering the current
    // in-memory weekly cache, scoped to whatever the last 7-day fetch covers.
    const kevMap = await fetchKevCatalog();
    const cves = await fetchWeeklyCves(kevMap);
    const needle = q?.toLowerCase();
    const filtered = cves.filter((c) =>
      (!needle ||
        c.cveId.toLowerCase().includes(needle) ||
        c.description.toLowerCase().includes(needle) ||
        (c.vendor ?? "").toLowerCase().includes(needle)) &&
      (!cwe || c.cweIds.includes(cwe)) &&
      (!severity || c.severity === severity) &&
      (!exploited || c.isKnownExploited) &&
      (minEpss === undefined || (c.epssScore ?? -1) >= minEpss)
    );
    const matches = (minEpss === undefined
      ? filtered
      : [...filtered].sort((a, b) => (b.epssScore ?? 0) - (a.epssScore ?? 0))
    ).slice(0, limit);
    res.json(matches);
  } catch (err) {
    req.log.error({ err }, "Failed to search CVEs");
    res.status(502).json({ error: "Failed to search CVE data" });
  }
});

router.get("/cves/trend", async (req: Request, res: Response) => {
  try {
    const query = parseRequest(GetCvesTrendQueryParams, req.query, req, res);
    if (!query) return;
    const buckets = await loadTrendBuckets(query.days ?? 30);
    res.json(buckets ?? []);
  } catch (err) {
    req.log.error({ err }, "Failed to load CVE trend");
    res.status(502).json({ error: "Failed to fetch CVE trend data" });
  }
});

router.get("/cves/summary", async (_req: Request, res: Response) => {
  try {
    const kevMap = await fetchKevCatalog();
    const cves = await fetchDailyCves(kevMap);

    const summary = {
      reportDate: new Intl.DateTimeFormat("en-CA", { timeZone: "Australia/Brisbane" }).format(new Date()),
      totalNew: cves.length,
      critical: cves.filter((c) => c.severity === "CRITICAL").length,
      high: cves.filter((c) => c.severity === "HIGH").length,
      medium: cves.filter((c) => c.severity === "MEDIUM").length,
      low: cves.filter((c) => c.severity === "LOW").length,
      patched: cves.filter((c) => c.hasKnownPatch).length,
      unpatched: cves.filter((c) => !c.hasKnownPatch).length,
      knownExploited: cves.filter((c) => c.isKnownExploited).length,
      newKevEntries: 0, // KEV additions today not directly queryable without date diff
      topVendors: (() => {
        const counts = new Map<string, number>();
        for (const cve of cves) {
          if (cve.vendor) {
            counts.set(cve.vendor, (counts.get(cve.vendor) ?? 0) + 1);
          }
        }
        return Array.from(counts.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([vendor, count]) => ({ vendor, count }));
      })(),
    };

    res.json(summary);
  } catch (err) {
    _req.log.error({ err }, "Failed to compute CVE summary");
    res.status(502).json({ error: "Failed to fetch summary data" });
  }
});

router.get("/cves/digest", async (req: Request, res: Response) => {
  try {
    const kevMap = await fetchKevCatalog();
    const cves = await fetchWeeklyCves(kevMap);

    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

    // Build per-platform groups
    const ALL_PLATFORMS: Platform[] = [
      "Windows", "macOS", "Linux", "iOS", "Android",
      "Network", "Server", "Cloud", "Browser", "Firmware", "Other",
    ];

    const platformGroups = ALL_PLATFORMS.map((platform) => {
      const group = cves.filter((c) => c.platforms.includes(platform));
      const topCves = [...group]
        .sort((a, b) => {
          const sa = severityOrder[a.severity ?? ""] ?? 4;
          const sb = severityOrder[b.severity ?? ""] ?? 4;
          if (sa !== sb) return sa - sb;
          return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
        })
        .slice(0, 5);

      return {
        platform,
        total: group.length,
        critical: group.filter((c) => c.severity === "CRITICAL").length,
        high: group.filter((c) => c.severity === "HIGH").length,
        medium: group.filter((c) => c.severity === "MEDIUM").length,
        low: group.filter((c) => c.severity === "LOW").length,
        patched: group.filter((c) => c.hasKnownPatch).length,
        unpatched: group.filter((c) => !c.hasKnownPatch).length,
        knownExploited: group.filter((c) => c.isKnownExploited).length,
        topCves,
      };
    }).filter((g) => g.total > 0)
      .sort((a, b) => b.total - a.total);

    // Build daily trend (one entry per calendar day in the window)
    const dayMap = new Map<string, { total: number; critical: number; high: number; medium: number; low: number }>();
    for (let d = 0; d < 7; d++) {
      const date = new Date(weekAgo.getTime() + d * 24 * 60 * 60 * 1000);
      const key = date.toISOString().split("T")[0];
      dayMap.set(key, { total: 0, critical: 0, high: 0, medium: 0, low: 0 });
    }
    for (const cve of cves) {
      const day = cve.publishedDate.split("T")[0];
      const entry = dayMap.get(day);
      if (entry) {
        entry.total++;
        if (cve.severity === "CRITICAL") entry.critical++;
        else if (cve.severity === "HIGH") entry.high++;
        else if (cve.severity === "MEDIUM") entry.medium++;
        else if (cve.severity === "LOW") entry.low++;
      }
    }

    const dailyTrend = Array.from(dayMap.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([date, counts]) => ({ date, ...counts }));

    const digest = {
      startDate: weekAgo.toISOString().split("T")[0],
      endDate: now.toISOString().split("T")[0],
      totalCves: cves.length,
      critical: cves.filter((c) => c.severity === "CRITICAL").length,
      high: cves.filter((c) => c.severity === "HIGH").length,
      patched: cves.filter((c) => c.hasKnownPatch).length,
      knownExploited: cves.filter((c) => c.isKnownExploited).length,
      platformGroups,
      dailyTrend,
    };

    res.json(digest);
  } catch (err) {
    req.log.error({ err }, "Failed to build weekly digest");
    res.status(502).json({ error: "Failed to fetch weekly digest data" });
  }
});

router.get("/cves/:cveId", async (req: Request, res: Response) => {
  try {
    const params = parseRequest(GetCveByIdParams, req.params, req, res);
    if (!params) return;
    const { cveId } = params;
    const kevMap = await fetchKevCatalog();

    // Try daily cache first
    const dailyCves = getCache<CveEntry[]>("daily_cves");
    const fromCache = dailyCves?.find((c) => c.cveId === cveId);
    if (fromCache) {
      const detail = { ...fromCache, kevDetails: kevMap.get(cveId) ?? null };
      return res.json(detail);
    }

    // Fetch directly from NVD by CVE ID
    logger.info({ cveId }, "Fetching CVE by ID from NVD");
    const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
    url.searchParams.set("cveId", cveId);

    const nvdRes = await fetch(url.toString(), {
      headers: NVD_HEADERS,
      signal: AbortSignal.timeout(15000),
    });

    if (nvdRes.status === 404 || nvdRes.status === 204) {
      return res.status(404).json({ error: "CVE not found" });
    }

    if (!nvdRes.ok) {
      return res.status(502).json({ error: `NVD API error: ${nvdRes.status}` });
    }

    const json = (await nvdRes.json()) as { vulnerabilities?: NvdCveItem[] };
    const item = json.vulnerabilities?.[0];
    if (!item) {
      return res.status(404).json({ error: "CVE not found" });
    }

    const [entry] = await enrichEntries([extractFromNvdItem(item, kevMap)]);
    const detail = { ...entry, kevDetails: kevMap.get(cveId) ?? null };
    return res.json(detail);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch CVE by ID");
    return res.status(502).json({ error: "Failed to fetch CVE data" });
  }
});

export default router;
