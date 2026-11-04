// Cold-start KEV behaviour, in its own file (node:test runs each file in a separate process) so
// the module-level caches start empty.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startTestServer, healthyUpstream, FIXTURE_KEV, type TestServer } from "../test-support/fake-upstreams";

let srv: TestServer;
let cisaBodyRead: () => void;
const cisaBodyWasRead = new Promise<void>((resolve) => (cisaBodyRead = resolve));
let bodyReadBeforeNvdFinished = false;

function trackedResponse(body: string): Response {
  const res = new Response(body);
  const json = res.json.bind(res);
  return Object.assign(res, {
    json: async () => {
      cisaBodyRead();
      return json();
    },
  });
}

before(async () => {
  srv = await startTestServer((url) => {
    if (url.hostname === "www.cisa.gov") return trackedResponse(JSON.stringify(FIXTURE_KEV));
    if (url.searchParams.has("hasKev") && !url.searchParams.has("kevStartDate")) {
      // A slow NVD: answers once CISA's body is read, or gives up and fails shortly after.
      const outcome = Promise.race([
        cisaBodyWasRead.then(() => true),
        new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 200)),
      ]);
      return outcome.then((read) => {
        bodyReadBeforeNvdFinished = read;
        return new Response("slow", { status: 503 });
      }) as unknown as Response;
    }
    return healthyUpstream(url);
  });
});
after(async () => {
  await srv.close();
});

test("parallel cold requests share one KEV fetch, and a slow NVD can't time out CISA's body", async () => {
  const responses = await Promise.all([1, 2, 3].map(() => fetch(`${srv.baseUrl}/api/cves/kev`)));
  assert.deepEqual(responses.map((r) => r.status), [200, 200, 200]);
  assert.equal(srv.upstreamCalls.filter((u) => u.includes("www.cisa.gov")).length, 1);
  assert.equal(bodyReadBeforeNvdFinished, true);
});
