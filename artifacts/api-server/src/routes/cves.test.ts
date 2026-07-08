import { test } from "node:test";
import assert from "node:assert/strict";
import { detectPlatforms, detectDeviceType } from "./cves";

test("detectPlatforms: matches Windows from a CPE string", () => {
  const cpes = ["cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"];
  assert.deepEqual(detectPlatforms(cpes, ""), ["Windows"]);
});

test("detectPlatforms: matches Linux distro CPEs", () => {
  const cpes = ["cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*"];
  assert.deepEqual(detectPlatforms(cpes, ""), ["Linux"]);
});

test("detectPlatforms: falls back to description keywords when CPE data is absent", () => {
  assert.deepEqual(detectPlatforms([], "A vulnerability in the Linux kernel scheduler"), ["Linux"]);
});

test("detectPlatforms: returns Other when nothing matches", () => {
  assert.deepEqual(detectPlatforms([], "some unrelated text with no platform hints"), ["Other"]);
});

test("detectPlatforms: malformed CPE strings (too few parts) are skipped, not thrown", () => {
  assert.deepEqual(detectPlatforms(["not-a-cpe-string"], "windows update issue"), ["Windows"]);
});

test("detectPlatforms: can return multiple distinct platforms across CPEs", () => {
  const cpes = [
    "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
    "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
  ];
  const result = detectPlatforms(cpes, "");
  assert.ok(result.includes("Windows"));
  assert.ok(result.includes("Browser"));
});

test("detectDeviceType: VM hypervisor products are Endpoint VM, not Server", () => {
  const cpes = ["cpe:2.3:a:vmware:workstation:17.0:*:*:*:*:*:*:*"];
  assert.equal(detectDeviceType(cpes, ""), "Endpoint VM");
});

test("detectDeviceType: Windows Server CPEs classify as Server, not Endpoint", () => {
  const cpes = ["cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*"];
  assert.equal(detectDeviceType(cpes, ""), "Server");
});

test("detectDeviceType: mobile OS CPEs classify as Mobile", () => {
  const cpes = ["cpe:2.3:o:google:android:13.0:*:*:*:*:*:*:*"];
  assert.equal(detectDeviceType(cpes, ""), "Mobile");
});

test("detectDeviceType: falls back to Other with no signal", () => {
  assert.equal(detectDeviceType([], "no useful signal here"), "Other");
});
