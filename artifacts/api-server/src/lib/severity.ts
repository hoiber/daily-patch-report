export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null;

/** CVSS base score to qualitative rating (v3/v4 bands). */
export function parseSeverity(score: number | null): Severity {
  if (score === null) return null;
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}
