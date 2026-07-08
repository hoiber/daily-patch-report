import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRssItems, classifyIssue } from "./patch-tuesday";

test("parseRssItems: parses a standard RSS 2.0 <item>", () => {
  const xml = `
    <rss><channel>
      <item>
        <title>Windows 11 update causes BSOD on some devices</title>
        <link>https://example.com/post/1</link>
        <pubDate>Tue, 08 Jul 2026 10:00:00 GMT</pubDate>
        <description><![CDATA[Some users report a blue screen after installing.]]></description>
        <category>Windows</category>
        <category>Bugs</category>
      </item>
    </channel></rss>
  `;
  const items = parseRssItems(xml);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, "Windows 11 update causes BSOD on some devices");
  assert.equal(items[0].link, "https://example.com/post/1");
  assert.equal(items[0].description, "Some users report a blue screen after installing.");
  assert.deepEqual(items[0].categories, ["Windows", "Bugs"]);
});

test("parseRssItems: parses an Atom <entry> (Reddit-style feed)", () => {
  const xml = `
    <feed>
      <entry>
        <title>PSA: latest patch breaks printing on shared printers</title>
        <link href="https://reddit.com/r/sysadmin/abc123" rel="alternate"/>
        <updated>2026-07-08T10:00:00Z</updated>
        <content type="html">Printing stopped working after the update.</content>
      </entry>
    </feed>
  `;
  const items = parseRssItems(xml);
  assert.equal(items.length, 1);
  assert.equal(items[0].link, "https://reddit.com/r/sysadmin/abc123");
  assert.equal(items[0].description, "Printing stopped working after the update.");
});

test("parseRssItems: drops unsafe (non-http) links", () => {
  const xml = `
    <rss><channel>
      <item>
        <title>Suspicious post</title>
        <link>javascript:alert(1)</link>
        <description>test</description>
      </item>
    </channel></rss>
  `;
  const items = parseRssItems(xml);
  // title+link are both required to keep an item, and the unsafe link is blanked out
  assert.equal(items.length, 0);
});

test("parseRssItems: returns an empty array for XML with no item/entry blocks", () => {
  assert.deepEqual(parseRssItems("<rss><channel></channel></rss>"), []);
});

test("classifyIssue: BSOD/crash language classifies as Bug", () => {
  assert.equal(classifyIssue("Update causes BSOD", "device crashes on boot"), "Bug");
});

test("classifyIssue: 'stopped working after' language classifies as Regression", () => {
  assert.equal(classifyIssue("Printing broken", "printer stops working after the update"), "Regression");
});

test("classifyIssue: rollback/mitigation language classifies as Workaround", () => {
  assert.equal(classifyIssue("Fix for the issue", "workaround: uninstall the update"), "Workaround");
});

test("classifyIssue: falls back to Discussion with no matching keywords", () => {
  assert.equal(classifyIssue("Just a general post", "nothing notable here"), "Discussion");
});

test("classifyIssue: checks Bug before Regression when both could match", () => {
  // "crash" alone should hit the Bug rule, which is checked first.
  assert.equal(classifyIssue("App crash", "the app crashes randomly"), "Bug");
});
