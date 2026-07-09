import { Router, type IRouter, type Request, type Response } from "express";
import * as metrics from "../lib/metrics";
import { isDbConfigured } from "../lib/cve-store";

const router: IRouter = Router();

const FETCH_SOURCES = ["daily", "weekly", "kev", "ptReleases", "ptDigest"] as const;

router.get("/metrics", (_req: Request, res: Response) => {
  const cacheHits: Record<string, number> = {};
  const cacheMisses: Record<string, number> = {};
  for (const [key, value] of Object.entries(metrics.allCounters())) {
    if (key.startsWith("cache.hit.")) cacheHits[key.slice("cache.hit.".length)] = value;
    else if (key.startsWith("cache.miss.")) cacheMisses[key.slice("cache.miss.".length)] = value;
  }

  const lastFetch: Record<string, string | null> = {};
  const lastError: Record<string, { message: string; at: string } | null> = {};
  for (const source of FETCH_SOURCES) {
    lastFetch[source] = metrics.getGauge(`lastFetch.${source}`) ?? null;
    const raw = metrics.getGauge(`lastError.${source}`);
    lastError[source] = raw ? JSON.parse(raw) : null;
  }

  res.json({
    cacheHits,
    cacheMisses,
    lastFetch,
    lastError,
    db: {
      configured: isDbConfigured(),
      writeSuccesses: metrics.getCounter("db.write.success"),
      writeFailures: metrics.getCounter("db.write.failure"),
    },
  });
});

export default router;
