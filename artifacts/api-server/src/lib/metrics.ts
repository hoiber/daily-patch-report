/**
 * In-process counter/gauge registry for operational visibility into the two
 * independent in-memory caches (cves.ts, patch-tuesday.ts) and the Postgres
 * write path. Resets on restart — this is a live snapshot, not a durable metric
 * store. Surfaced via GET /metrics (routes/metrics.ts).
 */

const counters = new Map<string, number>();
const gauges = new Map<string, string>();

export function increment(key: string): void {
  counters.set(key, (counters.get(key) ?? 0) + 1);
}

export function getCounter(key: string): number {
  return counters.get(key) ?? 0;
}

export function allCounters(): Record<string, number> {
  return Object.fromEntries(counters);
}

export function setGauge(key: string, value: string): void {
  gauges.set(key, value);
}

export function getGauge(key: string): string | undefined {
  return gauges.get(key);
}

export function recordCacheHit(key: string): void {
  increment(`cache.hit.${key}`);
}

export function recordCacheMiss(key: string): void {
  increment(`cache.miss.${key}`);
}

/** Marks a successful upstream fetch and clears any previously recorded error for that source. */
export function recordFetchSuccess(source: string): void {
  setGauge(`lastFetch.${source}`, new Date().toISOString());
  gauges.delete(`lastError.${source}`);
}

export function recordFetchError(source: string, err: unknown): void {
  const message = err instanceof Error ? err.message : String(err);
  setGauge(`lastError.${source}`, JSON.stringify({ message, at: new Date().toISOString() }));
}
