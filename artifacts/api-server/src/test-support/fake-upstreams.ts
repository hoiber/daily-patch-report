// Test-only helpers for route-level tests: boot the real Express app on an ephemeral port with
// `globalThis.fetch` swapped for a fake that answers NVD / CISA KEV requests from fixtures, so
// the full request path (routing, validation, caching, KEV cross-referencing, response shape)
// runs without touching the network. Requests to the test server itself pass through.

import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

export const NOW = new Date();
const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3600_000).toISOString().replace("Z", "");

export function nvdItem(opts: {
  id: string;
  score: number;
  publishedHoursAgo: number;
  description: string;
  patchUrl?: string;
  cpe?: string;
}) {
  return {
    cve: {
      id: opts.id,
      published: hoursAgo(opts.publishedHoursAgo),
      lastModified: hoursAgo(opts.publishedHoursAgo),
      descriptions: [{ lang: "en", value: opts.description }],
      metrics: {
        cvssMetricV31: [{ cvssData: { baseScore: opts.score, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }],
      },
      references: opts.patchUrl ? [{ url: opts.patchUrl, tags: ["Patch"] }] : [{ url: "https://example.com/writeup" }],
      configurations: opts.cpe ? [{ nodes: [{ cpeMatch: [{ criteria: opts.cpe }] }] }] : [],
    },
  };
}

export const FIXTURE_CVES = {
  CRITICAL: [
    nvdItem({
      id: "CVE-2026-0001",
      score: 9.8,
      publishedHoursAgo: 2,
      description: "Remote code execution in Microsoft Windows SMB server",
      patchUrl: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-0001",
      cpe: "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
    }),
    nvdItem({
      id: "CVE-2026-0002",
      score: 9.1,
      publishedHoursAgo: 72,
      description: "Authentication bypass in Example Router firmware",
      cpe: "cpe:2.3:h:examplecorp:router_x1:*:*:*:*:*:*:*:*",
    }),
  ],
  HIGH: [
    nvdItem({
      id: "CVE-2026-0003",
      score: 7.5,
      publishedHoursAgo: 5,
      description: "Heap overflow in Google Chrome V8",
      patchUrl: "https://chromereleases.googleblog.com/2026/10/stable-channel-update.html",
      cpe: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
    }),
  ],
  MEDIUM: [] as ReturnType<typeof nvdItem>[],
};

export const FIXTURE_KEV = {
  vulnerabilities: [
    {
      cveID: "CVE-2026-0002",
      vendorProject: "ExampleCorp",
      product: "Router X1",
      vulnerabilityName: "ExampleCorp Router X1 Authentication Bypass",
      dateAdded: NOW.toISOString().slice(0, 10),
      shortDescription: "Authentication bypass in Example Router firmware",
      requiredAction: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
      dueDate: NOW.toISOString().slice(0, 10),
      knownRansomwareCampaignUse: "Unknown",
    },
  ],
};

type Handler = (url: URL) => Response | undefined;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** Default upstream: NVD answers per cvssV3Severity / cveId / hasKev, CISA answers FIXTURE_KEV, anything else 503. */
export const healthyUpstream: Handler = (url) => {
  if (url.hostname === "services.nvd.nist.gov") {
    const sev = url.searchParams.get("cvssV3Severity") as keyof typeof FIXTURE_CVES | null;
    if (sev) return json({ totalResults: FIXTURE_CVES[sev].length, vulnerabilities: FIXTURE_CVES[sev] });
    const cveId = url.searchParams.get("cveId");
    if (cveId) {
      const all = [...FIXTURE_CVES.CRITICAL, ...FIXTURE_CVES.HIGH, ...FIXTURE_CVES.MEDIUM];
      const hit = all.filter((i) => i.cve.id === cveId);
      return json({ totalResults: hit.length, vulnerabilities: hit });
    }
    if (url.searchParams.has("hasKev")) {
      return json({ totalResults: 1, vulnerabilities: FIXTURE_CVES.CRITICAL.filter((i) => i.cve.id === "CVE-2026-0002") });
    }
  }
  if (url.hostname === "www.cisa.gov") return json(FIXTURE_KEV);
  return undefined;
};

export const failingUpstream: Handler = () => new Response("upstream exploded: secret-internal-detail", { status: 503 });

export interface TestServer {
  baseUrl: string;
  upstreamCalls: string[];
  close: () => Promise<void>;
}

export async function startTestServer(handler: Handler = healthyUpstream): Promise<TestServer> {
  // Set before the app (and cves.ts's module-level NVD_HEADERS) loads: with an API key the
  // weekly fetch runs its severity buckets concurrently instead of staggering them 6s/12s.
  process.env.NVD_API ??= "test-key";
  process.env.LOG_LEVEL ??= "silent";
  delete process.env.DATABASE_URL;

  const realFetch = globalThis.fetch;
  const upstreamCalls: string[] = [];
  let baseUrl = "";

  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (baseUrl && url.href.startsWith(baseUrl)) return realFetch(input, init);
    upstreamCalls.push(url.href);
    return handler(url) ?? new Response("not found", { status: 503 });
  }) as typeof fetch;

  const { default: app } = await import("../app");
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    baseUrl,
    upstreamCalls,
    close: () =>
      new Promise((resolve) => {
        globalThis.fetch = realFetch;
        server.close(() => resolve());
      }),
  };
}
