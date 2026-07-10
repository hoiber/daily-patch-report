import app from "./app";
import { logger } from "./lib/logger";
import { warmWeeklyCache, refreshCveCache } from "./routes/cves";

// Slightly longer than the weekly cache's 1-hour TTL, so each tick lands
// after the in-memory cache has actually expired and triggers a real
// re-fetch (fetchWeeklyCves's own cache check would otherwise just return
// the still-valid cached data and skip the fetch entirely).
const CACHE_REFRESH_INTERVAL_MS = 61 * 60 * 1000;

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");

  // Start warming the weekly CVE cache in the background.
  // This runs after the server is ready so it doesn't block startup.
  void warmWeeklyCache();

  // Proactively keep it warm afterward, so a page load never has to be the
  // thing that triggers a live NVD re-fetch.
  setInterval(() => void refreshCveCache(), CACHE_REFRESH_INTERVAL_MS);
});
