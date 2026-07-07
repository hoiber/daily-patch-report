import app from "./app";
import { logger } from "./lib/logger";
import { warmWeeklyCache } from "./routes/cves";

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
});
