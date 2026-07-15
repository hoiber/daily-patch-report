import { pgTable, text, real, integer, boolean, timestamp, jsonb, serial, index, primaryKey } from "drizzle-orm/pg-core";

// Current-state snapshot of each CVE api-server has computed from NVD/KEV,
// upserted by cveId on every weekly fetch. Lets a fresh instance warm its
// in-memory cache from Postgres instead of paying a cold NVD fetch.
export const cveSnapshots = pgTable("cve_snapshots", {
  cveId: text("cve_id").primaryKey(),
  description: text("description").notNull(),
  publishedDate: timestamp("published_date", { withTimezone: true }).notNull(),
  lastModifiedDate: timestamp("last_modified_date", { withTimezone: true }).notNull(),
  severity: text("severity"),
  cvssScore: real("cvss_score"),
  cvssVector: text("cvss_vector"),
  hasKnownPatch: boolean("has_known_patch").notNull(),
  isKnownExploited: boolean("is_known_exploited").notNull(),
  vendor: text("vendor"),
  deviceType: text("device_type").notNull(),
  platforms: jsonb("platforms").notNull().$type<string[]>(),
  affectedProducts: jsonb("affected_products").notNull().$type<string[]>(),
  patchUrls: jsonb("patch_urls").notNull().$type<string[]>(),
  cweIds: jsonb("cwe_ids").notNull().$type<string[]>(),
  // Named to avoid the SQL reserved word `references`; the public API's
  // CveEntry.references field name is unaffected by this internal rename.
  referenceUrls: jsonb("reference_urls").notNull().$type<string[]>(),
  firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
});

// Append-only log of tracked-field changes, populated by diffing each
// fetch's results against the previously stored snapshot.
export const cveChanges = pgTable(
  "cve_changes",
  {
    id: serial("id").primaryKey(),
    cveId: text("cve_id").notNull().references(() => cveSnapshots.cveId),
    changedAt: timestamp("changed_at", { withTimezone: true }).notNull().defaultNow(),
    field: text("field").notNull(),
    oldValue: text("old_value"),
    newValue: text("new_value"),
  },
  (table) => [
    index("cve_changes_cve_id_idx").on(table.cveId),
    index("cve_changes_changed_at_idx").on(table.changedAt),
  ],
);

// Per-CVE detail as parsed from the ios-security-vulnerability-formatter report,
// stored alongside each apple_releases row rather than a separate table since it's
// only ever read/written as a unit with its parent release.
export interface AppleCveJson {
  cveId: string;
  description: string | null;
  activelyExploited: boolean;
  versionNote: string | null;
  nvdUrl: string;
}

// One row per (platform, version) ever seen. Upserted on every fetch — a new
// version produces a new row (accumulating history), an already-seen version
// updates in place (e.g. if the advisory gains CVEs after initial publish).
// Never deleted, so this is api-server's own history/changelog for Apple
// releases, independent of the upstream tool (which only ever reports "the
// latest N releases right now").
export const appleReleases = pgTable(
  "apple_releases",
  {
    platform: text("platform").notNull(),
    version: text("version").notNull(),
    updateName: text("update_name"),
    releaseDate: text("release_date").notNull(),
    cveCount: integer("cve_count").notNull(),
    securityInfoUrl: text("security_info_url"),
    activelyExploited: boolean("actively_exploited").notNull(),
    cves: jsonb("cves").notNull().$type<AppleCveJson[]>(),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.platform, table.version] }),
    index("apple_releases_platform_idx").on(table.platform),
  ],
);
