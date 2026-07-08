# Threat Model

## Project Overview

This project is a CVE reporting application composed of a React dashboard (`artifacts/cve-dashboard`) and an Express API (`artifacts/api-server`) that aggregates vulnerability data from NVD, CISA KEV, Microsoft MSRC, and several RSS feeds. `cve-dashboard` is the only service with a public Railway domain; `api-server` sits on Railway's private network and is reached solely through `cve-dashboard`'s own server-side proxy (`vite preview`'s `preview.proxy`, driven by `API_INTERNAL_URL`) — it has no public domain of its own. Neither service has an authentication layer, so any internet client that can reach the dashboard must still be treated as a potential attacker; it just no longer has a direct network path to `api-server`. (`api-server`'s permissive CORS middleware is not a production trust boundary — it exists for the local-dev case where `VITE_API_URL` points the dashboard directly at a separately-running `api-server`, bypassing the proxy.) `api-server` optionally persists to a staging Postgres database (`lib/db`, via `DATABASE_URL`) as a durable cache and change-history sidecar for the same vulnerability data it already serves live — no new sensitive-data class, but it is now part of the threat surface (see Assets/Trust Boundaries below). The mockup sandbox artifact is development-only and out of scope unless production reachability is later demonstrated.

## Assets

- **Service availability** — the API performs live aggregation against multiple third-party feeds and can become unavailable if expensive fetch/parse paths are abused.
- **Integrity of vulnerability data shown to users** — incorrect or attacker-manipulated upstream data could mislead patching decisions.
- **Deployment and runtime secrets** — environment variables, deployment cookies, any bearer tokens used by shared client libraries, and `DATABASE_URL` (Postgres connection string, including credentials) must not leak through logs or client code.
- **User trust in outbound links and advisories** — the dashboard renders upstream references and patch links that influence operator actions.

## Trust Boundaries

- **Browser to dashboard to API** — all dashboard interactions cross into the Express API via `cve-dashboard`'s server-side proxy. Query strings and path parameters are untrusted and must not trigger disproportionate server work; the proxy hop doesn't add authorization, only network isolation.
- **API to third-party data providers** — the API fetches JSON/XML/RSS from NVD, CISA, MSRC, Reddit, BleepingComputer, and Microsoft Tech Community. These sources are outside the application's control and their data must be treated as untrusted.
- **API to in-memory cache** — cache keys and cache-miss behavior affect whether a request is cheap or triggers expensive upstream fan-out.
- **API to Postgres** — `api-server` optionally reads/writes `cveSnapshots`/`cveChanges` (`src/lib/cve-store.ts`); this is a best-effort sidecar, not a required dependency — a slow or unreachable database must never delay or break the live-aggregation response (writes are fire-and-forget, reads are wrapped and degrade to empty/`null`). The new `GET /cves/changes` route's `limit` query param is untrusted input like any other and must stay bounded.
- **Production vs dev-only artifacts** — `artifacts/mockup-sandbox` is assumed non-production; production scanning should focus on `artifacts/api-server`, `artifacts/cve-dashboard`, and shared `lib/*` packages unless deployment scope changes.
- **Public internet to dashboard** — there is no edge control (network restriction, auth wall, or IP allowlist) limiting who can reach `cve-dashboard`, so any internet client is a potential attacker with full access to application endpoints via the proxy. `api-server` itself has no public network path in production.

## Scan Anchors

- Production API entry points: `artifacts/api-server/src/app.ts`, `artifacts/api-server/src/routes/*.ts`
- Production frontend entry points: `artifacts/cve-dashboard/src/App.tsx`, `artifacts/cve-dashboard/src/pages/*.tsx`
- Shared API contract/client: `lib/api-spec/openapi.yaml`, `lib/api-client-react/src/*`, `lib/api-zod/src/generated/api.ts`
- Highest-risk areas: third-party fetch and parsing logic in `artifacts/api-server/src/routes/cves.ts` and `artifacts/api-server/src/routes/patch-tuesday.ts`
- Dev-only area usually ignored: `artifacts/mockup-sandbox/**`

## Threat Categories

### Tampering

The API converts untrusted third-party CVE, KEV, CVRF, and RSS data into dashboard-visible fields and links. The service must only derive structured output from expected fields, validate any request parameters that influence upstream selection, and avoid letting untrusted data alter server control flow beyond intended parsing and filtering. Any outbound link derived from upstream content must be validated or normalized before it is presented to users as a trusted patch or reference destination.

### Information Disclosure

The application is primarily read-only, but shared client utilities can attach bearer tokens and the server processes deployment requests. Authorization headers, cookies, and any future session material must never be logged or exposed in client bundles. Error responses should stay generic and avoid reflecting internal fetch errors beyond safe status summaries.

### Denial of Service

Availability is the main security concern for this project. Several routes can trigger slow upstream API calls, XML/RSS parsing, and large response assembly. The service must ensure that untrusted clients cannot amplify work with cache-busting inputs, concurrent cache-miss stampedes, or unbounded repeated requests. Expensive endpoints should coalesce identical work and degrade gracefully when upstream providers are slow or rate-limit the application. `api-server` applies a per-IP fixed-window rate limit (`src/middlewares/rate-limit.ts`, 120 req/min) as a blanket mitigation against sustained abuse; this depends on `cve-dashboard`'s proxy forwarding the real client IP via `X-Forwarded-For` (`xfwd: true` in `vite.config.ts`) and `api-server` trusting that one hop (`app.set("trust proxy", 1)`) — if that proxy hop is ever changed, verify per-client identification still works, or every user will collapse onto one rate-limit bucket.

### Elevation of Privilege

The current application has no in-app role model and no deployment-level access control, so there is no authorization boundary at all today. If any future authenticated or admin-only features are added, route protection must be enforced server-side and shared API clients must not encourage token handling patterns that leak privileged credentials into the browser.
