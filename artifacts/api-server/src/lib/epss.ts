import { logger } from "./logger";
import * as metrics from "./metrics";

// EPSS (Exploit Prediction Scoring System, FIRST.org): daily probability (0–1) that a CVE will
// be exploited in the next 30 days, plus its percentile among all scored CVEs. Complements CVSS
// (impact) and KEV (already exploited) for deciding what to patch first.
//
// Scores update once a day upstream, so results are cached per CVE for 24h and fetched in
// batches only from the scheduled weekly refresh and the single-CVE detail route — never fanned
// out per list request (see threat_model.md). Failures are non-fatal: entries just keep null.

const EPSS_URL = "https://api.first.org/data/v1/epss";
const BATCH_SIZE = 100; // keeps the comma-separated `cve=` query well under URL length limits
const TTL_MS = 24 * 60 * 60 * 1000;
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

export interface EpssScore {
  epssScore: number;
  epssPercentile: number;
}

const cache = new Map<string, { value: EpssScore | null; expiresAt: number }>();

function cached(cveId: string): EpssScore | null | undefined {
  const hit = cache.get(cveId);
  if (!hit) return undefined;
  if (hit.expiresAt < Date.now()) {
    cache.delete(cveId);
    return undefined;
  }
  return hit.value;
}

async function fetchBatch(cveIds: string[]): Promise<void> {
  const url = `${EPSS_URL}?cve=${cveIds.join(",")}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error(`EPSS fetch failed: ${res.status}`);
  const json = (await res.json()) as { data?: Array<{ cve: string; epss: string; percentile: string }> };

  const expiresAt = Date.now() + TTL_MS;
  const found = new Set<string>();
  for (const row of json.data ?? []) {
    const epssScore = Number(row.epss);
    const epssPercentile = Number(row.percentile);
    if (!Number.isFinite(epssScore) || !Number.isFinite(epssPercentile)) continue;
    cache.set(row.cve, { value: { epssScore, epssPercentile }, expiresAt });
    found.add(row.cve);
  }
  // Brand-new CVEs often aren't scored yet; cache the miss so they aren't re-requested all day.
  for (const id of cveIds) if (!found.has(id)) cache.set(id, { value: null, expiresAt });
}

/** Returns EPSS scores for the given CVEs, fetching any not cached. Never throws. */
export async function getEpssScores(cveIds: string[]): Promise<Map<string, EpssScore>> {
  const ids = [...new Set(cveIds.filter((id) => CVE_ID.test(id)))];
  const missing = ids.filter((id) => cached(id) === undefined);

  for (let i = 0; i < missing.length; i += BATCH_SIZE) {
    try {
      await fetchBatch(missing.slice(i, i + BATCH_SIZE));
      metrics.recordFetchSuccess("epss");
    } catch (err) {
      metrics.recordFetchError("epss", err);
      logger.warn({ err }, "EPSS fetch failed; continuing without scores");
      break; // upstream is struggling — don't hammer it with the remaining batches
    }
  }

  const out = new Map<string, EpssScore>();
  for (const id of ids) {
    const score = cached(id);
    if (score) out.set(id, score);
  }
  return out;
}

/** Copies EPSS scores onto entries (null where unavailable). */
export function applyEpss<T extends { cveId: string }>(
  entries: T[],
  scores: Map<string, EpssScore>,
): Array<T & { epssScore: number | null; epssPercentile: number | null }> {
  return entries.map((e) => {
    const s = scores.get(e.cveId);
    return { ...e, epssScore: s?.epssScore ?? null, epssPercentile: s?.epssPercentile ?? null };
  });
}
