import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { createClient } from "../src/client.js";
import { checkHost } from "../src/check.js";
import { startMockServer } from "./mock-server.js";

let server;
let dir;

before(async () => {
  server = await startMockServer();
  dir = await mkdtemp(join(tmpdir(), "lts-cli-"));
  await writeFile(join(dir, "README.md"), "https://good.dev/\nhttps://good.dev/again\n");
  await writeFile(join(dir, "bad.html"), '<a href="https://malware-site.com/">x</a>');
});
after(() => server.close());

async function cli(args, env = {}) {
  let stdout = "";
  let stderr = "";
  const code = await main(args, {
    env: { LINKTHREATSCAN_API_KEY: "org-key", LINKTHREATSCAN_API_URL: server.url, ...env },
    stdout: { write: (s) => (stdout += s) },
    stderr: { write: (s) => (stderr += s) },
    cwd: dir,
  });
  return { code, stdout, stderr };
}

test("scan exits 0 for clean links and 1 for a malicious one", async () => {
  const clean = await cli(["scan", "README.md"]);
  assert.equal(clean.code, 0, clean.stderr);
  assert.match(clean.stdout, /clean {8}good\.dev {2}8,200/);
  assert.match(clean.stdout, /2 links to 1 host: 1 clean, 0 malicious/);

  const bad = await cli(["scan"]);
  assert.equal(bad.code, 1);
  assert.match(bad.stdout, /✗ MALICIOUS {4}malware-site\.com {2}500 {2}bad\.html:1/);
});

test("check takes URLs, and --json / --report write the report", async () => {
  const report = join(dir, "out.json");
  const r = await cli(["check", "https://malware-two.com/a?b=c", "--json", "--report", report, "--max-age", "0"]);
  assert.equal(r.code, 1);
  const printed = JSON.parse(r.stdout);
  assert.equal(printed.summary.malicious, 1);
  assert.equal(printed.results[0].links[0].url, "https://malware-two.com/a?b=c");
  assert.deepEqual(JSON.parse(await readFile(report, "utf8")).summary, printed.summary);
});

test("usage errors and API refusals exit 2", async () => {
  assert.equal((await cli(["frobnicate"])).code, 2);
  assert.equal((await cli(["check"])).code, 2);
  assert.equal((await cli(["scan", "--min-score", "-1"])).code, 2);
  assert.equal((await cli(["scan", "--private", "--public"])).code, 2);
  const personal = await cli(["scan"], { LINKTHREATSCAN_API_KEY: "personal-key" });
  assert.equal(personal.code, 2);
  assert.match(personal.stdout, /for organizations/);
  const unpaid = await cli(["check", "https://good.dev"], { LINKTHREATSCAN_API_KEY: "unpaid-key" });
  assert.match(unpaid.stdout, /requires an active subscription/);
  const missing = await cli(["scan"], { LINKTHREATSCAN_API_KEY: "" });
  assert.match(missing.stderr, /No API key/);
});

test("--private and --public are passed through, absent means the organization's default", async () => {
  const from = server.received.length;
  await cli(["check", "https://p1.dev", "--private"]);
  await cli(["check", "https://p2.dev", "--public"]);
  await cli(["check", "https://p3.dev"]);
  assert.deepEqual(
    server.received.slice(from).map((b) => b.private),
    [true, false, undefined],
  );
});

test("a rate limit and a busy scanner are waited out, not reported as failures", async () => {
  for (const opts of [{ rateLimitFirstCheck: true }, { busyFirstCheck: true }]) {
    const s = await startMockServer(opts);
    try {
      const client = createClient({ apiKey: "org-key", apiUrl: s.url });
      const started = Date.now();
      const r = await checkHost(client, { host: "good.dev", url: "https://good.dev/", occurrences: [] });
      assert.equal(r.status, "CLEAN", JSON.stringify(r));
      assert.ok(Date.now() - started >= 900, "waited for Retry-After");
      assert.equal(s.calls.length, 2);
    } finally {
      await s.close();
    }
  }
});

test("an unreachable API stops the run after its retries", async () => {
  const client = createClient({ apiKey: "org-key", apiUrl: "http://127.0.0.1:9", networkRetryDelaysMs: [10] });
  const r = await checkHost(client, { host: "good.dev", url: "https://good.dev/", occurrences: [] });
  assert.equal(r.status, "ERROR");
  assert.match(r.error, /Could not reach/);
  assert.equal(r.fatal, true);
});
