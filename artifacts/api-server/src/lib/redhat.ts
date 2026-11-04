import { logger } from "./logger";
import * as metrics from "./metrics";

// Red Hat's Security Data API lists the errata (RHSA advisories) that fix a CVE. An RHSA is firm
// evidence a fix has shipped, which NVD often can't give for CVEs it hasn't analysed yet, so it
// only ever adds a patch: no RHSA says nothing either way, because Red Hat may not ship the
// product at all.
//
// Fetched in batches, cached per CVE for 24h including misses, and only from the scheduled refresh
// and the single-CVE detail route (see threat_model.md). Failures are non-fatal, and an expired
// result is kept until a lookup succeeds so an outage can't flip a CVE back to unpatched.

const REDHAT_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json";
const BATCH_SIZE = 100;
const TTL_MS = 24 * 60 * 60 * 1000;
const MAX_ADVISORIES = 3;
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;
const RHSA_ID = /^RHSA-\d{4}:\d+$/;

const cache = new Map<string, { value: string[]; expiresAt: number }>();

async function fetchBatch(cveIds: string[]): Promise<void> {
  const res = await fetch(`${REDHAT_URL}?ids=${cveIds.join(",")}`, { signal: AbortSignal.timeout(20000) });
  const expiresAt = Date.now() + TTL_MS;
  // Red Hat may answer 404 when it knows none of the batch; that's a valid "no data".
  if (!res.ok && res.status !== 404) throw new Error(`Red Hat fetch failed: ${res.status}`);
  const rows = res.ok ? ((await res.json()) as Array<{ CVE?: string; advisories?: unknown }>) : [];

  const found = new Set<string>();
  for (const row of rows) {
    if (!row.CVE) continue;
    const advisories = Array.isArray(row.advisories) ? row.advisories : [];
    const rhsa = advisories.filter((a): a is string => typeof a === "string" && RHSA_ID.test(a));
    cache.set(row.CVE, { value: rhsa.slice(0, MAX_ADVISORIES), expiresAt });
    found.add(row.CVE);
  }
  for (const id of cveIds) if (!found.has(id)) cache.set(id, { value: [], expiresAt });
}

/** Returns RHSA IDs for the given CVEs, leaving out those with none. Never throws. */
export async function getRedhatAdvisories(cveIds: string[]): Promise<Map<string, string[]>> {
  const ids = [...new Set(cveIds.filter((id) => CVE_ID.test(id)))];
  const now = Date.now();
  const missing = ids.filter((id) => (cache.get(id)?.expiresAt ?? 0) < now);

  for (let i = 0; i < missing.length; i += BATCH_SIZE) {
    try {
      await fetchBatch(missing.slice(i, i + BATCH_SIZE));
      metrics.recordFetchSuccess("redhat");
    } catch (err) {
      metrics.recordFetchError("redhat", err);
      logger.warn({ err }, "Red Hat fetch failed; continuing with cached advisories");
      break; // upstream is struggling: don't hammer it with the remaining batches
    }
  }

  const out = new Map<string, string[]>();
  for (const id of ids) {
    const advisories = cache.get(id)?.value;
    if (advisories?.length) out.set(id, advisories);
  }
  return out;
}

/** Marks CVEs with an RHSA as patched and puts the errata links first. */
export function applyRedhatAdvisories<T extends { cveId: string; hasKnownPatch: boolean; patchUrls: string[] }>(
  entries: T[],
  advisories: Map<string, string[]>,
): T[] {
  return entries.map((e) => {
    const rhsa = advisories.get(e.cveId);
    if (!rhsa) return e;
    const urls = rhsa.map((id) => `https://access.redhat.com/errata/${id}`);
    return { ...e, hasKnownPatch: true, patchUrls: [...new Set([...urls, ...e.patchUrls])].slice(0, 5) };
  });
}

/** Test hook: forget all cached results. */
export function resetRedhatCache(): void {
  cache.clear();
}
