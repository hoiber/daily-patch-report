# Threat Model

## Project Overview

This project is a CVE reporting application composed of a React dashboard (`artifacts/cve-dashboard`) and an Express API (`artifacts/api-server`) that aggregates vulnerability data from NVD, CISA KEV, Microsoft MSRC, and several RSS feeds. The app deploys as two separate public Railway services with no authentication layer and permissive CORS between them, so there is no privacy boundary reducing exposure — any internet client that can reach either service must be treated as a potential attacker. The mockup sandbox artifact is development-only and out of scope unless production reachability is later demonstrated.

## Assets

- **Service availability** — the API performs live aggregation against multiple third-party feeds and can become unavailable if expensive fetch/parse paths are abused.
- **Integrity of vulnerability data shown to users** — incorrect or attacker-manipulated upstream data could mislead patching decisions.
- **Deployment and runtime secrets** — environment variables, deployment cookies, and any bearer tokens used by shared client libraries must not leak through logs or client code.
- **User trust in outbound links and advisories** — the dashboard renders upstream references and patch links that influence operator actions.

## Trust Boundaries

- **Browser to API** — all dashboard interactions cross into the Express API. Query strings and path parameters are untrusted and must not trigger disproportionate server work.
- **API to third-party data providers** — the API fetches JSON/XML/RSS from NVD, CISA, MSRC, Reddit, BleepingComputer, and Microsoft Tech Community. These sources are outside the application's control and their data must be treated as untrusted.
- **API to in-memory cache** — cache keys and cache-miss behavior affect whether a request is cheap or triggers expensive upstream fan-out.
- **Production vs dev-only artifacts** — `artifacts/mockup-sandbox` is assumed non-production; production scanning should focus on `artifacts/api-server`, `artifacts/cve-dashboard`, and shared `lib/*` packages unless deployment scope changes.
- **Public internet to application logic** — there is no edge control (network restriction, auth wall, or IP allowlist) limiting who can reach either Railway service, so any internet client is a potential attacker with full access to application endpoints.

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

Availability is the main security concern for this project. Several routes can trigger slow upstream API calls, XML/RSS parsing, and large response assembly. The service must ensure that untrusted clients cannot amplify work with cache-busting inputs, concurrent cache-miss stampedes, or unbounded repeated requests. Expensive endpoints should coalesce identical work and degrade gracefully when upstream providers are slow or rate-limit the application.

### Elevation of Privilege

The current application has no in-app role model and no deployment-level access control, so there is no authorization boundary at all today. If any future authenticated or admin-only features are added, route protection must be enforced server-side and shared API clients must not encourage token handling patterns that leak privileged credentials into the browser.
