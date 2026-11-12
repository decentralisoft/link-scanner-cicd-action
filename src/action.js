// GitHub Action entry point (see action.yml). Reads the `with:` inputs from
// INPUT_* variables, finds and checks the links, and reports through the
// runner's files: step outputs, a job summary table, and an error annotation
// at every line that links to a malicious host.
// No @actions/* dependency — the protocol is a handful of env files.

import { appendFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { detectCiContext } from "./ci.js";
import { createClient, DEFAULT_API_URL } from "./client.js";
import { bySeverity, checkHosts, Status, summarize, thresholdOf, where } from "./check.js";
import { buildReport, findLinks } from "./find.js";

const input = (name, fallback = "") => {
  const v = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`];
  return v === undefined || v.trim() === "" ? fallback : v.trim();
};
const bool = (name, fallback) => {
  const v = input(name, String(fallback)).toLowerCase();
  if (["true", "yes", "1"].includes(v)) return true;
  if (["false", "no", "0"].includes(v)) return false;
  throw new Error(`Input '${name}' must be true or false, got '${v}'.`);
};
const int = (name, fallback) => {
  const n = Number(input(name, String(fallback)));
  if (!Number.isInteger(n) || n < 1) throw new Error(`Input '${name}' must be a positive whole number.`);
  return n;
};
const lines = (name, fallback = "") =>
  input(name, fallback)
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith("#"));

// Workflow commands: https://docs.github.com/actions/reference/workflow-commands-for-github-actions
const escapeData = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const escapeProp = (s) => escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
export const command = (name, props, message) => {
  const p = Object.entries(props)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k}=${escapeProp(v)}`)
    .join(",");
  process.stdout.write(`::${name}${p ? " " + p : ""}::${escapeData(message)}\n`);
};

async function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  const delimiter = `ghadelimiter_${randomUUID()}`;
  await appendFile(file, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
}

/** Annotations per malicious host: enough to find them all, not a flood. */
const ANNOTATIONS_PER_HOST = 20;
/** Rows in the job summary; the JSON report has every one. */
const SUMMARY_ROWS = 300;

const cell = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");
const fmt = (n) => (typeof n === "number" ? n.toLocaleString("en-US") : "—");
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** Inputs the organization's CI/CD page replaced. */
const MOVED_INPUTS = ["min-score", "max-age"];

function detail(r) {
  switch (r.status) {
    case Status.MALICIOUS:
      return `scored ${fmt(r.score)}/10,000, below ${fmt(r.minScore)}` + (r.threats.length ? `; listed by ${r.threats.join(", ")}` : "");
    case Status.CLEAN:
      return r.reused ? "recent result reused" : "";
    case Status.SKIPPED:
      return "switched off for this repository on linkthreatscan.com";
    default:
      return r.error || "";
  }
}

function summaryMarkdown(summary, results, minScore) {
  const icon = { CLEAN: "✅", MALICIOUS: "🛑", ERROR: "⚠️", UNREACHABLE: "➖", SKIPPED: "⏭️" };
  const headline =
    summary.result === "malicious"
      ? `🛑 **${plural(summary.malicious, "malicious host")} linked from this repository.**`
      : summary.result === "error"
        ? `⚠️ **${plural(summary.errors, "host")} could not be checked.**`
        : `✅ **All ${plural(summary.clean, "linked host")} scored ${fmt(minScore)} or more.**`;
  const sorted = [...results].sort(bySeverity);
  const rows = sorted.slice(0, SUMMARY_ROWS).map((r) => {
    const found = r.occurrences.slice(0, 3).map((o) => `\`${cell(where(o))}\``);
    if (r.occurrences.length > 3) found.push(`+${r.occurrences.length - 3} more`);
    const report = r.reportUrl ? `[report](${r.reportUrl})` : "";
    return `| ${icon[r.status]} ${r.status} | \`${cell(r.host)}\` | ${fmt(r.score)} | ${found.join(", ")} | ${cell(detail(r))} | ${report} |`;
  });
  return [
    "### LinkThreatScan link check",
    "",
    headline,
    "",
    `${plural(summary.links, "link")} to ${plural(summary.hosts, "host")} · ${summary.clean} clean · ${summary.malicious} malicious · ` +
      `${summary.unreachable} unreachable · ${summary.errors} failed · ${summary.reused} reused from the last checks` +
      (summary.skipped ? ` · ${summary.skipped} switched off` : ""),
    "",
    "| Result | Host | Score | Found in | Detail | |",
    "|---|---|---|---|---|---|",
    ...rows,
    ...(sorted.length > SUMMARY_ROWS ? ["", `…and ${sorted.length - SUMMARY_ROWS} more hosts in the JSON report.`] : []),
    "",
  ].join("\n");
}

async function setCounts(values) {
  for (const [name, value] of Object.entries(values)) await setOutput(name, String(value));
}

export async function run() {
  const apiKey = input("api-key");
  if (apiKey) process.stdout.write(`::add-mask::${apiKey}\n`);
  const patterns = lines("files", ".");
  const urls = lines("urls");
  const excludeHosts = lines("exclude-hosts").flatMap((l) => l.split(",")).map((s) => s.trim()).filter(Boolean);
  const ifNoLinks = input("if-no-links-found", "ignore");
  if (!["error", "warn", "ignore"].includes(ifNoLinks)) {
    throw new Error("Input 'if-no-links-found' must be error, warn or ignore.");
  }
  for (const name of MOVED_INPUTS) {
    if (input(name)) {
      command(
        "warning",
        { title: "Input ignored" },
        `'${name}' is no longer read: the threshold and how long a result is reused are set on your organization's CI/CD page at linkthreatscan.com. Remove it from the workflow.`,
      );
    }
  }
  const failOnMalicious = bool("fail-on-malicious", true);
  const failOnUnreachable = bool("fail-on-unreachable", false);
  const failOnError = bool("fail-on-error", true);
  const maxHosts = int("max-hosts", 500);
  const concurrency = int("concurrency", 4);
  const timeoutMs = int("timeout", 300) * 1000;
  const isPrivate = input("private") === "" ? undefined : bool("private", false);
  const cwd = process.env.GITHUB_WORKSPACE || process.cwd();

  const client = createClient({ apiKey, apiUrl: input("api-url", DEFAULT_API_URL), timeoutMs });
  const { groups, filesRead, unmatched, invalidUrls } = await findLinks({ patterns, urls, excludeHosts, cwd });
  for (const p of unmatched) command("warning", {}, `No files match '${p}'.`);
  for (const u of invalidUrls) command("warning", {}, `Not a public http(s) URL, skipped: '${u}'.`);

  if (groups.length === 0) {
    const message = `No links to check in ${plural(filesRead, "file")}.`;
    await setOutput("result", "none");
    await setCounts({ links: 0, hosts: 0, malicious: 0, unreachable: 0, errors: 0, skipped: 0 });
    if (ifNoLinks === "error") throw new Error(message);
    if (ifNoLinks === "warn") command("warning", {}, message);
    else console.log(message);
    return 0;
  }
  if (groups.length > maxHosts) {
    throw new Error(
      `Found links to ${groups.length} hosts, more than max-hosts (${maxHosts}). Each new host is a scan on your organization's quota: ` +
        "narrow 'files', add 'exclude-hosts', or raise 'max-hosts'.",
    );
  }

  const ci = detectCiContext(process.env);
  const links = groups.reduce((n, g) => n + g.occurrences.length, 0);
  console.log(`Checking ${plural(links, "link")} to ${plural(groups.length, "host")} (from ${plural(filesRead, "file")}) with LinkThreatScan…`);
  const results = await checkHosts(client, groups, {
    concurrency,
    ci,
    private: isPrivate,
    batchId: randomUUID(),
    onResult: (r) => {
      if (r.status === Status.MALICIOUS) {
        const message = `${r.host} ${detail(r)}.${r.reportUrl ? ` Report: ${r.reportUrl}` : ""}`;
        for (const o of r.occurrences.slice(0, ANNOTATIONS_PER_HOST)) {
          const file = o.line ? o.file : undefined;
          command("error", { file, line: o.line, col: o.column, title: "Malicious link" }, `${o.url} — ${message}`);
        }
        if (r.occurrences.length > ANNOTATIONS_PER_HOST) {
          command("error", { title: "Malicious link" }, `${r.host}: ${r.occurrences.length - ANNOTATIONS_PER_HOST} more links, listed in the report.`);
        }
      } else if (r.status === Status.UNREACHABLE) {
        const o = r.occurrences[0];
        const props = { file: o.line ? o.file : undefined, line: o.line, col: o.column, title: "Link could not be scanned" };
        command(failOnUnreachable ? "error" : "warning", props, `${o.url} — ${r.error}`);
      } else if (r.status === Status.ERROR) {
        command(failOnError ? "error" : "warning", { title: "Check failed" }, `${r.host}: ${r.error}`);
      } else if (r.status === Status.SKIPPED) {
        console.log(`  skipped  ${r.host.padEnd(40)} switched off on linkthreatscan.com`);
      } else {
        console.log(`  clean  ${r.host.padEnd(40)} ${fmt(r.score).padStart(6)}${r.reused ? "  (reused)" : ""}`);
      }
    },
  });
  const summary = summarize(results);
  const minScore = thresholdOf(results);

  const reportPath = join(process.env.RUNNER_TEMP || cwd, `linkthreatscan-report-${Date.now()}.json`);
  const report = buildReport({ apiUrl: client.apiUrl, ci, minScore, summary, results });
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
  await setOutput("result", summary.result);
  await setCounts({
    links: summary.links,
    hosts: summary.hosts,
    malicious: summary.malicious,
    unreachable: summary.unreachable,
    errors: summary.errors,
    skipped: summary.skipped,
  });
  await setOutput("report", reportPath);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, summaryMarkdown(summary, results, minScore));
  }

  console.log(
    `\n${plural(summary.hosts, "host")}: ${summary.clean} clean, ${summary.malicious} malicious, ` +
      `${summary.unreachable} unreachable, ${summary.errors} failed, ${summary.skipped} skipped (${summary.reused} reused).`,
  );
  if (summary.malicious && failOnMalicious) {
    command("error", {}, `${plural(summary.malicious, "malicious host")} linked from this repository.`);
    return 1;
  }
  if (summary.errors && failOnError) {
    command("error", {}, `${plural(summary.errors, "host")} could not be checked.`);
    return 1;
  }
  if (summary.unreachable && failOnUnreachable) {
    command("error", {}, `${plural(summary.unreachable, "host")} could not be scanned.`);
    return 1;
  }
  return 0;
}
