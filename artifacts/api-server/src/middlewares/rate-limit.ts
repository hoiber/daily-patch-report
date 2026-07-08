import type { NextFunction, Request, Response } from "express";

interface Window {
  count: number;
  resetAt: number;
}

const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 120;
const SWEEP_INTERVAL_MS = 5 * 60_000;

const windows = new Map<string, Window>();

// Without this, `windows` would grow forever as distinct client IPs show up.
setInterval(() => {
  const now = Date.now();
  for (const [key, window] of windows) {
    if (now > window.resetAt) windows.delete(key);
  }
}, SWEEP_INTERVAL_MS).unref();

/**
 * Fixed-window per-IP rate limiter. Relies on Express's `req.ip`, which only
 * reflects the real client address if `trust proxy` is configured (see app.ts) —
 * otherwise every request behind Railway's edge would collapse onto one key.
 */
export function rateLimit(req: Request, res: Response, next: NextFunction): void {
  const key = req.ip ?? "unknown";
  const now = Date.now();

  let window = windows.get(key);
  if (!window || now > window.resetAt) {
    window = { count: 0, resetAt: now + WINDOW_MS };
    windows.set(key, window);
  }

  window.count += 1;

  if (window.count > MAX_REQUESTS_PER_WINDOW) {
    res.setHeader("Retry-After", Math.ceil((window.resetAt - now) / 1000).toString());
    res.status(429).json({ error: "Too many requests" });
    return;
  }

  next();
}
