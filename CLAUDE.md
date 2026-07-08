# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A CVE / vulnerability reporting app: an Express API (`artifacts/api-server`) that aggregates data live from NVD, CISA KEV, Microsoft MSRC, and several RSS/Atom feeds (Reddit, BleepingComputer, MS Tech Community), and a React dashboard (`artifacts/cve-dashboard`) that displays it. `cve-dashboard` is the only publicly reachable service; `api-server` sits on Railway's private network (see Deployment below). See `threat_model.md` for the full security posture — there's no authentication layer anywhere, so any client that can reach the dashboard is treated as untrusted; availability/DoS via upstream fan-out is the primary concern.

## Commands

- `pnpm --filter @workspace/api-server run dev` — run the API server (requires `PORT` env var; builds then starts)
- `pnpm --filter @workspace/cve-dashboard run dev` — run the dashboard (requires `PORT` and `BASE_PATH` env vars)
- `pnpm run typecheck` — full typecheck: `tsc --build` for `lib/*` project-referenced packages, then per-package `tsc --noEmit` for `artifacts/*` and `scripts`
- `pnpm run build` — typecheck + build all packages (`pnpm -r --if-present run build`)
- `pnpm --filter @workspace/api-spec run codegen` — regenerate `lib/api-zod` and `lib/api-client-react` from `lib/api-spec/openapi.yaml` (also re-typechecks the libs afterward)
- `pnpm --filter @workspace/db run push` / `run push-force` — push Drizzle schema to Postgres (dev only)
- Package manager is enforced: the root `preinstall` script fails if you're not using `pnpm` (no npm/yarn lockfiles allowed)
- `pnpm --filter @workspace/api-server run test` — runs `tsx --test` (Node's built-in test runner) against `src/**/*.test.ts`; currently the only package with tests. Covers the fragile, hand-rolled logic: platform/device-type inference (`cves.ts`) and the RSS/Atom parser + issue classifier (`patch-tuesday.ts`). No other package has a test runner configured yet.

Required env vars: `PORT` (api-server and cve-dashboard, no default — fails fast if unset), `BASE_PATH` (cve-dashboard vite config, no default). Optional: `NVD_API` (api-server) — an NVD API key, sent as the `apiKey` header on all NVD requests; raises the rate limit from 1 req/6s to 50 req/30s and lets the weekly-fetch severity buckets run concurrently instead of staggered. `DATABASE_URL` is only needed if `lib/db` is actually wired into a service (currently unused — see Workspace layout).

## Workspace layout

pnpm workspace (`pnpm-workspace.yaml`), packages under `artifacts/*`, `lib/*`, `lib/integrations/*`, `scripts`.

- `artifacts/api-server` — Express 5 API, bundled to a single ESM file via esbuild (`build.mjs`) and run with `node --enable-source-maps`
- `artifacts/cve-dashboard` — production React dashboard (Vite, wouter router, TanStack Query, Radix/shadcn UI, Tailwind v4)
- `artifacts/mockup-sandbox` — dev-only component playground; has its own Vite plugin (`mockupPreviewPlugin.ts`) that globs `src/components/mockups/**/*.tsx` and hot-generates an import map for live preview. Not part of production; out of scope for security review unless that changes.
- `lib/api-spec` — `openapi.yaml` is the **single source of truth** for the API contract. `orval.config.ts` drives codegen into both `lib/api-zod` and `lib/api-client-react` — never hand-edit files under either package's `generated/` folder.
- `lib/api-zod` — generated Zod schemas, imported by `api-server` routes to validate query/path params (e.g. `GetDailyCvesQueryParams.parse(req.query)`)
- `lib/api-client-react` — generated TanStack Query hooks + a hand-written `custom-fetch.ts` mutator (handles base-URL prefixing for non-web runtimes, bearer-token injection, JSON/text/blob body parsing, structured `ApiError`/`ResponseParseError`)
- `lib/db` — Drizzle ORM + `pg`, Postgres. The schema (`src/schema/index.ts`) is currently just a template/placeholder — the app is not persisting anything to Postgres yet, it's a live-aggregation service. Not depended on by any deployed service currently (`api-server` dropped the dependency since it never imported it). A staging Postgres instance has been provisioned in Railway, but no code consumes it yet — treat wiring it in as a separate, deliberate decision rather than assuming it's already load-bearing.
- `scripts` — misc standalone `tsx` scripts, not part of the build/deploy graph

TypeScript: root `tsconfig.json` uses project references for `lib/db`, `lib/api-client-react`, `lib/api-zod` only (built via `tsc --build`). Packages under `artifacts/*` and `scripts` are *not* referenced — they typecheck independently via their own `tsc -p tsconfig.json --noEmit`. `tsconfig.base.json` is shared strict-mode config (`strictNullChecks`, `noImplicitAny`, etc., but `noUnusedLocals`/`strictFunctionTypes` off).

## API server architecture

Everything in `artifacts/api-server/src/routes/*.ts` is a **live aggregator with an in-memory cache**, not a database-backed CRUD API:

- `cves.ts` fetches NVD (`services.nvd.nist.gov`) for CVE data and CISA's KEV JSON feed, cross-referencing KEV entries onto CVEs to set `isKnownExploited`. Also derives `platform`/`deviceType` from CPE strings (and vendor/description text as fallback) via large rule tables — there's no upstream field for this, it's inferred here.
- `patch-tuesday.ts` fetches Microsoft's MSRC CVRF v2 JSON API for monthly release digests, plus a hand-rolled RSS/Atom parser (regex-based, no XML library) that scrapes Reddit/BleepingComputer/MS Tech Community feeds for real-world post-patch breakage reports, classified into categories (Bug/Regression/Workaround/Advisory/Analysis) by keyword rules.
- Each route file keeps its **own** private `Map`-based TTL cache (not shared) — don't assume a cache key in one file is visible to the other.
- The weekly CVE fetch dedupes concurrent in-flight requests via a shared `Promise` (`weeklyFetchInFlight`) to avoid stampeding NVD on cache miss; NVD's public (no API key) rate limit is respected by staggering severity-bucket requests with `setTimeout` (0s/6s/12s).
- `warmWeeklyCache()` runs once, fire-and-forget, right after the server starts listening (`index.ts`) so the first real request doesn't pay the cold-fetch cost.
- Routes validate query/path params using the generated Zod schemas from `@workspace/api-zod`; upstream fetch/parse failures are caught and returned as `502` with a generic message (never reflect raw upstream errors to clients — see `threat_model.md`).

When changing API request/response shapes: edit `lib/api-spec/openapi.yaml` first, then run the `codegen` script — don't hand-edit generated types, and don't add new Zod validation shapes by hand in `api-zod`.

## Build notes

- `api-server`'s `build.mjs` bundles with esbuild into a single `.mjs`, with a long `external` allowlist for native/unbundleable packages and a banner shim that restores CJS-style `require`/`__dirname` inside the bundled ESM output (needed because some bundled deps, e.g. Express, are CJS). `pino` is handled via `esbuild-plugin-pino`, which bundles the worker transports (`pino-pretty`, etc.) as standalone sibling files in `dist/` — in production (`NODE_ENV=production`), `lib/logger.ts` skips the `pino-pretty` transport entirely, so `dist/` is fully self-contained at runtime with no `node_modules` needed.
- `pnpm-workspace.yaml` sets `minimumReleaseAge: 1440` (1-day delay before a newly published npm version can be installed) as a supply-chain defense — do not remove or zero this out; only add trusted-publisher exceptions to `minimumReleaseAgeExclude`, and remove them again once the window passes.
- The workspace `overrides` exclude prebuilt native binaries for platforms other than the deploy target from some packages (esbuild/lightningcss/rollup/tailwind-oxide) — this doesn't block local installs on other platforms (pnpm still resolves the correct optional platform binary for whatever machine runs `install`), it just trims the lockfile/download set for CI and deploy images.

## Deployment (Railway)

`api-server` and `cve-dashboard` deploy as **two separate Railway services** from this repo, each built from its own `Dockerfile` (`artifacts/api-server/Dockerfile`, `artifacts/cve-dashboard/Dockerfile`) with a matching `railway.json` declaring the Dockerfile path. Both Dockerfiles expect the **build context to be the repo root** (not the artifact subfolder) because pnpm workspace deps (`workspace:*`) require sibling packages to be present — when creating each Railway service, leave "Root Directory" unset and only set "Dockerfile Path".

- `api-server`'s image is multi-stage: build stage runs `pnpm install` + the package's `build` script, runtime stage copies out only `dist/` (see Build notes above for why that's sufficient) onto a bare `node:24-slim`.
- `cve-dashboard` is a single-stage image: it runs `vite build` then serves the static output via the existing `serve` script (`vite preview --host 0.0.0.0`, which handles SPA fallback routing), so `node_modules` (incl. `vite`) stays in the final image.
- **`api-server` has no public Railway domain** — `cve-dashboard` is the only public surface. The generated API client calls relative `/api/...` paths (see `custom-fetch.ts` / `main.tsx`), and `cve-dashboard`'s `vite preview` server proxies those server-side to `api-server` over Railway's private network (`vite.config.ts` `preview.proxy`), driven by an `API_INTERNAL_URL` **runtime** variable (e.g. a reference variable like `http://${{api-server.RAILWAY_PRIVATE_DOMAIN}}:${{api-server.PORT}}`) set on the dashboard service. `api-server`'s permissive CORS (`app.use(cors())`) isn't for this path — it exists for the separate, dev-only case of `VITE_API_URL` (a **build-time** arg baked into the client bundle) pointing the dashboard directly at a standalone, publicly-reachable `api-server` instead of going through the proxy.
- `api-server`'s `railway.json` sets `healthcheckPath: /api/healthz`; `cve-dashboard`'s sets `healthcheckPath: /`.
- Each service's Railway "Custom Start Command" must be left unset (or removed if previously set) so the Dockerfile's own `CMD` runs — a stale start command from before these Dockerfiles existed silently overrides `CMD` and is the most likely cause if a deploy builds fine but a container never starts, or `cve-dashboard` serves a dev-server response (`/@vite/client` injected into the HTML) instead of the built bundle.
- Railway's config-as-code (`.railway/railway.ts` / `railway config apply`) is **not** used here — it can't coexist with the per-service `railway.json` files (Railway refuses to manage a service from both). `railway.json` is the source of truth for build/deploy settings; anything else (env vars, domains) is managed directly via `railway variable`/`railway domain` or the dashboard.
