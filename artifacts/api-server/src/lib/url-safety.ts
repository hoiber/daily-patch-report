const SAFE_PROTOCOLS = new Set(["http:", "https:"]);

/**
 * Upstream feeds (NVD references, MSRC remediations, RSS/Atom links) are untrusted
 * per threat_model.md — reject anything that isn't a plain http(s) URL before it
 * reaches a rendered <a href>, so a javascript:/data: URI can't ride along.
 */
export function isSafeHttpUrl(url: string | undefined | null): url is string {
  if (!url) return false;
  try {
    return SAFE_PROTOCOLS.has(new URL(url).protocol);
  } catch {
    return false;
  }
}
