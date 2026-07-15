import { sql, desc, eq } from "drizzle-orm";
import { db, appleReleases, type AppleCveJson } from "@workspace/db";
import { logger } from "./logger";
import { increment } from "./metrics";

type Platform = "ios" | "macos";

interface AppleReleaseLike {
  version: string | null;
  updateName: string | null;
  releaseDate: string;
  cveCount: number;
  securityInfoUrl: string | null;
  activelyExploited: boolean;
}

export interface AppleReleaseHistoryEntry {
  platform: Platform;
  version: string;
  updateName: string | null;
  releaseDate: string;
  cveCount: number;
  securityInfoUrl: string | null;
  activelyExploited: boolean;
  firstSeenAt: string;
  lastSeenAt: string;
}

/** Upserts one (platform, version) release row. Best-effort: a Postgres outage must never break the live proxy response. */
export async function saveAppleRelease(
  platform: Platform,
  release: AppleReleaseLike,
  cves: AppleCveJson[],
): Promise<void> {
  if (!db || !release.version) return;

  try {
    const now = new Date();
    await db
      .insert(appleReleases)
      .values({
        platform,
        version: release.version,
        updateName: release.updateName,
        releaseDate: release.releaseDate,
        cveCount: release.cveCount,
        securityInfoUrl: release.securityInfoUrl,
        activelyExploited: release.activelyExploited,
        cves,
        lastSeenAt: now,
      })
      .onConflictDoUpdate({
        target: [appleReleases.platform, appleReleases.version],
        // `excluded` is Postgres's pseudo-table holding the row that was attempted
        // for insert — update everything except firstSeenAt (set once, on first insert).
        set: {
          updateName: sql`excluded.update_name`,
          releaseDate: sql`excluded.release_date`,
          cveCount: sql`excluded.cve_count`,
          securityInfoUrl: sql`excluded.security_info_url`,
          activelyExploited: sql`excluded.actively_exploited`,
          cves: sql`excluded.cves`,
          lastSeenAt: sql`excluded.last_seen_at`,
        },
      });
    increment("db.write.success");
  } catch (err) {
    increment("db.write.failure");
    logger.warn({ err, platform, version: release.version }, "Failed to persist Apple release to Postgres");
  }
}

/** Most recent release per platform, used to warm the in-memory cache on a cold start. */
export async function loadLatestAppleReleases(): Promise<
  Record<Platform, { release: AppleReleaseHistoryEntry; cves: AppleCveJson[] } | null>
> {
  const result: Record<Platform, { release: AppleReleaseHistoryEntry; cves: AppleCveJson[] } | null> = {
    ios: null,
    macos: null,
  };
  if (!db) return result;

  try {
    for (const platform of ["ios", "macos"] as const) {
      const [row] = await db
        .select()
        .from(appleReleases)
        .where(eq(appleReleases.platform, platform))
        .orderBy(desc(appleReleases.lastSeenAt))
        .limit(1);
      if (!row) continue;
      result[platform] = {
        release: {
          platform,
          version: row.version,
          updateName: row.updateName,
          releaseDate: row.releaseDate,
          cveCount: row.cveCount,
          securityInfoUrl: row.securityInfoUrl,
          activelyExploited: row.activelyExploited,
          firstSeenAt: row.firstSeenAt.toISOString(),
          lastSeenAt: row.lastSeenAt.toISOString(),
        },
        cves: row.cves,
      };
    }
  } catch (err) {
    logger.warn({ err }, "Failed to load latest Apple releases from Postgres");
  }

  return result;
}

/** Full release history for one platform, newest first. Excludes the bulky per-CVE detail — see loadLatestAppleReleases for that. */
export async function loadAppleReleaseHistory(platform: Platform, limit: number): Promise<AppleReleaseHistoryEntry[]> {
  if (!db) return [];
  try {
    const rows = await db
      .select({
        version: appleReleases.version,
        updateName: appleReleases.updateName,
        releaseDate: appleReleases.releaseDate,
        cveCount: appleReleases.cveCount,
        securityInfoUrl: appleReleases.securityInfoUrl,
        activelyExploited: appleReleases.activelyExploited,
        firstSeenAt: appleReleases.firstSeenAt,
        lastSeenAt: appleReleases.lastSeenAt,
      })
      .from(appleReleases)
      .where(eq(appleReleases.platform, platform))
      .orderBy(desc(appleReleases.lastSeenAt))
      .limit(limit);

    return rows.map((row) => ({
      platform,
      version: row.version,
      updateName: row.updateName,
      releaseDate: row.releaseDate,
      cveCount: row.cveCount,
      securityInfoUrl: row.securityInfoUrl,
      activelyExploited: row.activelyExploited,
      firstSeenAt: row.firstSeenAt.toISOString(),
      lastSeenAt: row.lastSeenAt.toISOString(),
    }));
  } catch (err) {
    logger.warn({ err, platform }, "Failed to load Apple release history from Postgres");
    return [];
  }
}
