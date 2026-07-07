import { Router, type IRouter, type Request, type Response } from "express";
import {
  GetDailyCvesQueryParams,
  GetKevListQueryParams,
  GetCveByIdParams,
} from "@workspace/api-zod";
import { logger } from "../lib/logger";
import { isSafeHttpUrl } from "../lib/url-safety";

const router: IRouter = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

type Platform = "Windows" | "macOS" | "Linux" | "iOS" | "Android" | "Network" | "Server" | "Cloud" | "Browser" | "Firmware" | "Other";
type DeviceType = "Endpoint" | "Endpoint VM" | "Server" | "Network" | "Cloud" | "Mobile" | "Other";

interface CveEntry {
  cveId: string;
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null;
  cvssScore: number | null;
  cvssVector: string | null;
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
    return null;
  }
  return entry.data as T;
}

function setCache<T>(key: string, data: T, ttlMs: number): void {
  cache.set(key, { data, expiresAt: Date.now() + ttlMs });
}

const CVE_CACHE_TTL = 30 * 60 * 1000; // 30 minutes
const KEV_CACHE_TTL = 60 * 60 * 1000;        // 1 hour
const KEV_CVSS_CACHE_TTL = 6 * 60 * 60 * 1000; // 6 hours

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

/** Fetch CVSS scores for all KEV entries using NVD's isKevFilter param. Returns Map<cveId, {severity,cvssScore}>. */
async function fetchKevCvssMap(): Promise<Map<string, { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null; cvssScore: number | null }>> {
  const cached = getCache<Map<string, { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null; cvssScore: number | null }>>("kev_cvss_map");
  if (cached) return cached;

  logger.info("Fetching NVD CVSS data for KEV catalog");
  const map = new Map<string, { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null; cvssScore: number | null }>();

  let startIndex = 0;
  const pageSize = 2000;
  let totalResults = Infinity;

  while (startIndex < totalResults) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?isKevFilter&resultsPerPage=${pageSize}&startIndex=${startIndex}`;
    try {
      const res = await fetch(url, { headers: NVD_HEADERS, signal: AbortSignal.timeout(20000) });
      if (!res.ok) {
        logger.warn({ status: res.status }, "NVD KEV CVSS fetch failed, skipping enrichment");
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
      break;
    }
  }

  setCache("kev_cvss_map", map, KEV_CVSS_CACHE_TTL);
  return map;
}

// ─── Data fetchers ───────────────────────────────────────────────────────────

async function fetchKevCatalog(): Promise<Map<string, KevEntry>> {
  const cached = getCache<Map<string, KevEntry>>("kev_map");
  if (cached) return cached;

  logger.info("Fetching CISA KEV catalog");
  const [cisaRes, cvssMap] = await Promise.all([
    fetch(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      { signal: AbortSignal.timeout(15000) }
    ),
    fetchKevCvssMap().catch(() => new Map()),
  ]);
  if (!cisaRes.ok) throw new Error(`KEV fetch failed: ${cisaRes.status}`);

  const json = (await cisaRes.json()) as {
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
  };

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
  return map;
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

function detectPlatforms(cpeStrings: string[], description: string): Platform[] {
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

function detectDeviceType(cpeStrings: string[], description: string): DeviceType {
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

// ─── Severity ─────────────────────────────────────────────────────────────────

type NvdSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null;

function parseSeverity(score: number | null): NvdSeverity {
  if (score === null) return null;
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

function extractFromNvdItem(
  item: NvdCveItem,
  kevMap: Map<string, KevEntry>
): CveEntry {
  const cve = item.cve;
  const cveId = cve.id;

  const description =
    cve.descriptions?.find((d: { lang: string; value: string }) => d.lang === "en")
      ?.value ?? "No description available.";

  // CVSS v3.1 preferred, fall back to v3.0, then v2
  let cvssScore: number | null = null;
  let cvssVector: string | null = null;

  const metrics = cve.metrics ?? {};
  const v31 = metrics.cvssMetricV31?.[0];
  const v30 = metrics.cvssMetricV30?.[0];
  const v2 = metrics.cvssMetricV2?.[0];

  if (v31) {
    cvssScore = v31.cvssData?.baseScore ?? null;
    cvssVector = v31.cvssData?.vectorString ?? null;
  } else if (v30) {
    cvssScore = v30.cvssData?.baseScore ?? null;
    cvssVector = v30.cvssData?.vectorString ?? null;
  } else if (v2) {
    cvssScore = v2.cvssData?.baseScore ?? null;
    cvssVector = v2.cvssData?.vectorString ?? null;
  }

  const severity = parseSeverity(cvssScore);

  // References — detect patch/advisory URLs
  const references: string[] = [];
  const patchUrls: string[] = [];
  const patchKeywords = ["patch", "fix", "advisory", "update", "bulletin", "release", "security"];

  for (const ref of cve.references ?? []) {
    if (!isSafeHttpUrl(ref.url)) continue;
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
    descriptions?: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{ cvssData?: { baseScore: number; vectorString: string } }>;
      cvssMetricV30?: Array<{ cvssData?: { baseScore: number; vectorString: string } }>;
      cvssMetricV2?: Array<{ cvssData?: { baseScore: number; vectorString: string } }>;
    };
    references?: Array<{ url: string; tags?: string[] }>;
    configurations?: Array<{ nodes: NvdNode[] }>;
    weaknesses?: Array<{ description?: Array<{ value: string }> }>;
  };
}

async function fetchDailyCves(kevMap: Map<string, KevEntry>): Promise<CveEntry[]> {
  const cacheKey = "daily_cves";
  const cached = getCache<CveEntry[]>(cacheKey);
  if (cached) return cached;

  // Last 24 hours
  const now = new Date();
  const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const pubStartDate = yesterday.toISOString().replace(/\.\d{3}Z$/, ".000");
  const pubEndDate = now.toISOString().replace(/\.\d{3}Z$/, ".000");

  logger.info({ pubStartDate, pubEndDate }, "Fetching NVD daily CVEs");

  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("pubStartDate", pubStartDate);
  url.searchParams.set("pubEndDate", pubEndDate);
  url.searchParams.set("resultsPerPage", "200");

  const res = await fetch(url.toString(), {
    headers: NVD_HEADERS,
    signal: AbortSignal.timeout(30000),
  });

  if (!res.ok) {
    throw new Error(`NVD API error: ${res.status} ${res.statusText}`);
  }

  const json = (await res.json()) as { vulnerabilities?: NvdCveItem[] };
  const items = json.vulnerabilities ?? [];

  const entries = items.map((item) => extractFromNvdItem(item, kevMap));

  // Sort: patched first, then by severity, then by CVSS score desc
  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  entries.sort((a, b) => {
    if (a.hasKnownPatch !== b.hasKnownPatch) return a.hasKnownPatch ? -1 : 1;
    const sa = severityOrder[a.severity ?? ""] ?? 4;
    const sb = severityOrder[b.severity ?? ""] ?? 4;
    if (sa !== sb) return sa - sb;
    return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
  });

  setCache(cacheKey, entries, CVE_CACHE_TTL);
  return entries;
}

// ─── Weekly fetch (7 days) ───────────────────────────────────────────────────

// Deduplicate concurrent fetches: if a fetch is already in-flight,
// all callers await the same promise instead of starting duplicate requests.
let weeklyFetchInFlight: Promise<CveEntry[]> | null = null;

async function fetchWeeklyCves(kevMap: Map<string, KevEntry>): Promise<CveEntry[]> {
  const cacheKey = "weekly_cves";
  const cached = getCache<CveEntry[]>(cacheKey);
  if (cached) return cached;

  if (weeklyFetchInFlight) {
    logger.info("Weekly CVE fetch already in-flight, waiting…");
    return weeklyFetchInFlight;
  }

  const doFetch = async (): Promise<CveEntry[]> => {
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const pubStartDate = weekAgo.toISOString().replace(/\.\d{3}Z$/, ".000");
    const pubEndDate = now.toISOString().replace(/\.\d{3}Z$/, ".000");

    logger.info({ pubStartDate, pubEndDate }, "Fetching NVD weekly CVEs");

    // NVD's public (no-key) API is slow for large date ranges.
    // Strategy: make 3 small, fast, parallel requests filtered by severity.
    // Each severity bucket typically has <200 results and responds in 5–20 s.
    async function fetchSeverityPage(severity: string): Promise<CveEntry[]> {
      const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
      url.searchParams.set("pubStartDate", pubStartDate);
      url.searchParams.set("pubEndDate", pubEndDate);
      url.searchParams.set("cvssV3Severity", severity);
      url.searchParams.set("resultsPerPage", "500");

      const res = await fetch(url.toString(), {
        headers: NVD_HEADERS,
        signal: AbortSignal.timeout(60000),
      });

      if (!res.ok) {
        logger.warn({ severity, status: res.status }, "NVD severity fetch failed");
        return [];
      }

      const json = (await res.json()) as { vulnerabilities?: NvdCveItem[] };
      return (json.vulnerabilities ?? []).map((item) => extractFromNvdItem(item, kevMap));
    }

    // With an NVD_API key (50 req/30s) all 3 buckets can run concurrently.
    // Without one, stagger by 6s each to respect the public 1 req/6s limit.
    const hasApiKey = Boolean(process.env.NVD_API);
    const [critical, high, medium] = await Promise.all([
      fetchSeverityPage("CRITICAL"),
      hasApiKey
        ? fetchSeverityPage("HIGH")
        : new Promise<CveEntry[]>((resolve) =>
            setTimeout(() => resolve(fetchSeverityPage("HIGH")), 6000)
          ),
      hasApiKey
        ? fetchSeverityPage("MEDIUM")
        : new Promise<CveEntry[]>((resolve) =>
            setTimeout(() => resolve(fetchSeverityPage("MEDIUM")), 12000)
          ),
    ]);

    // Deduplicate (a CVE can theoretically appear in multiple buckets)
    const seen = new Set<string>();
    const allEntries: CveEntry[] = [];
    for (const entry of [...critical, ...high, ...medium]) {
      if (!seen.has(entry.cveId)) {
        seen.add(entry.cveId);
        allEntries.push(entry);
      }
    }

    setCache(cacheKey, allEntries, 60 * 60 * 1000); // 1-hour TTL
    return allEntries;
  };

  weeklyFetchInFlight = doFetch().finally(() => {
    weeklyFetchInFlight = null;
  });

  return weeklyFetchInFlight;
}

/** Fire-and-forget cache warmup — call after server starts */
export async function warmWeeklyCache(): Promise<void> {
  try {
    logger.info("Warming weekly CVE cache in background");
    const kevMap = await fetchKevCatalog();
    await fetchWeeklyCves(kevMap);
    logger.info("Weekly CVE cache warmed");
  } catch (err) {
    logger.warn({ err }, "Background weekly cache warmup failed (will retry on next request)");
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

router.get("/cves/weekly", async (req: Request, res: Response) => {
  try {
    const query = GetDailyCvesQueryParams.parse(req.query);
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
    const query = GetDailyCvesQueryParams.parse(req.query);
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
    GetKevListQueryParams.parse(req.query);
    const kevMap = await fetchKevCatalog();
    const entries = Array.from(kevMap.values())
      .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
    res.json(entries);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch KEV list");
    res.status(502).json({ error: "Failed to fetch CISA KEV data" });
  }
});

router.get("/cves/summary", async (_req: Request, res: Response) => {
  try {
    const kevMap = await fetchKevCatalog();
    const cves = await fetchDailyCves(kevMap);

    const summary = {
      reportDate: new Date().toISOString().split("T")[0],
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
    const { cveId } = GetCveByIdParams.parse(req.params);
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

    const entry = extractFromNvdItem(item, kevMap);
    const detail = { ...entry, kevDetails: kevMap.get(cveId) ?? null };
    return res.json(detail);
  } catch (err) {
    req.log.error({ err }, "Failed to fetch CVE by ID");
    return res.status(502).json({ error: "Failed to fetch CVE data" });
  }
});

export default router;
