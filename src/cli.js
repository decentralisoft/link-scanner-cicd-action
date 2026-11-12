// `linkthreatscan` — the command-line interface. Exit codes:
//   0  every linked host is clean (or could not be scanned, by default)
//   1  a malicious link was found
//   2  something failed: a check, the API, or the command line itself

import { writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { parseArgs } from "node:util";
import { detectCiContext } from "./ci.js";
import { createClient, DEFAULT_API_URL } from "./client.js";
import {
  bySeverity,
  checkHosts,
  DEFAULT_MAX_AGE_SECONDS,
  DEFAULT_MIN_SCORE,
  parseDuration,
  parseMinScore,
  Status,
  summarize,
  where,
} from "./check.js";
import { buildReport, findLinks } from "./find.js";
import { VERSION } from "./version.js";

export const EXIT = Object.freeze({ CLEAN: 0, MALICIOUS: 1, ERROR: 2 });

const HELP = `linkthreatscan ${VERSION} — find malicious links in your code with LinkThreatScan

Usage:
  linkthreatscan scan [path|glob]... [options]   Check the links in files (default: .)
  linkthreatscan check <url>... [options]        Check URLs given on the command line

Options:
  --url <url>              Also check this URL (repeatable)
  --exclude-host <host>    Skip a host and its subdomains, or a glob like *.corp.example (repeatable)
  --min-score <n>          A host scoring below this is malicious (0–10000, default ${DEFAULT_MIN_SCORE})
  --max-age <duration>     Reuse your organization's CI result for a host if newer (default 24h; 0 = always scan)
  --max-hosts <n>          Refuse to start above this many hosts (default 500)
  --private / --public     Whether new scans' reports are private (default: the organization's setting)
  --json                   Print the JSON report instead of text
  --report <file>          Also write the JSON report to <file>
  --concurrency <n>        Hosts checked in parallel (default 4)
  --timeout <seconds>      How long to wait for one host's verdict (default 300)
  --fail-on-unreachable    Exit 2 when a host cannot be scanned (does not resolve, not public)
  --no-fail-on-error       Exit 0 when checks fail but nothing is malicious
  --api-key <key>          An organization API key (default: $LINKTHREATSCAN_API_KEY — prefer the variable)
  --api-url <url>          API base URL (default: $LINKTHREATSCAN_API_URL or ${DEFAULT_API_URL})
  -h, --help               Show this help
  -v, --version            Show the version

Globs: *, **, ?, [abc], {a,b}; prefix with ! to exclude, e.g. 'docs/**' '!docs/archive/**'.
.git and node_modules are never read; lockfiles and source maps are skipped.
Only each host's origin (https://host/) is sent to the API, never a path or query.
Requires an organization's API key on a subscribed organization.
On GitHub Actions and GitLab CI, checks carry the repository, commit and run.
Exit codes: 0 clean, 1 malicious link found, 2 error.`;

const OPTIONS = {
  url: { type: "string", multiple: true },
  "exclude-host": { type: "string", multiple: true },
  "min-score": { type: "string" },
  "max-age": { type: "string" },
  "max-hosts": { type: "string" },
  private: { type: "boolean" },
  public: { type: "boolean" },
  json: { type: "boolean", default: false },
  report: { type: "string" },
  concurrency: { type: "string" },
  timeout: { type: "string" },
  "fail-on-unreachable": { type: "boolean", default: false },
  "no-fail-on-error": { type: "boolean", default: false },
  "api-key": { type: "string" },
  "api-url": { type: "string" },
  help: { type: "boolean", short: "h", default: false },
  version: { type: "boolean", short: "v", default: false },
};

class UsageError extends Error {}

function positiveInt(raw, name, fallback) {
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) throw new UsageError(`--${name} must be a positive whole number.`);
  return n;
}

const fmt = (n) => (typeof n === "number" ? n.toLocaleString("en-US") : "");

function formatLine(r) {
  const first = r.occurrences[0];
  const at = first ? `${where(first)}${r.occurrences.length > 1 ? ` (+${r.occurrences.length - 1})` : ""}` : "";
  switch (r.status) {
    case Status.CLEAN:
      return `  clean        ${r.host}  ${fmt(r.score)}${r.reused ? "  (reused)" : ""}`;
    case Status.MALICIOUS:
      return (
        `✗ MALICIOUS    ${r.host}  ${fmt(r.score)}  ${at}` +
        (r.threats.length ? `  listed by ${r.threats.join(", ")}` : "") +
        (r.reportUrl ? `\n               ${r.reportUrl}` : "")
      );
    case Status.UNREACHABLE:
      return `  unreachable  ${r.host}  ${r.error}  ${at}`.trimEnd();
    default:
      return `! error        ${r.host}  ${r.error || ""}`.trimEnd();
  }
}

/**
 * Run the CLI. Returns the exit code instead of exiting, so it can be tested.
 * @param {string[]} argv arguments after the program name
 * @param {{ env?: object, stdout?: object, stderr?: object, cwd?: string, fetch?: Function, clientOptions?: object }} io
 */
export async function main(argv, io = {}) {
  const env = io.env ?? process.env;
  const out = io.stdout ?? process.stdout;
  const err = io.stderr ?? process.stderr;
  const cwd = io.cwd ?? process.cwd();
  const print = (s = "") => out.write(s + "\n");
  const warn = (s) => err.write(s + "\n");

  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (e) {
    warn(`linkthreatscan: ${e.message}\nRun 'linkthreatscan --help' for usage.`);
    return EXIT.ERROR;
  }
  const { values: opts, positionals } = parsed;
  if (opts.version) {
    print(VERSION);
    return EXIT.CLEAN;
  }
  const [command, ...rest] = positionals;
  if (opts.help || !command) {
    print(HELP);
    return opts.help ? EXIT.CLEAN : EXIT.ERROR;
  }

  try {
    if (command !== "scan" && command !== "check") {
      throw new UsageError(`Unknown command '${command}'. Run 'linkthreatscan --help' for usage.`);
    }
    if (command === "check" && rest.length === 0) throw new UsageError("Usage: linkthreatscan check <url>...");
    if (opts.private && opts.public) throw new UsageError("Pass --private or --public, not both.");

    const minScore = parseMinScore(opts["min-score"] ?? DEFAULT_MIN_SCORE, "--min-score");
    const maxAge = parseDuration(opts["max-age"] ?? DEFAULT_MAX_AGE_SECONDS, "--max-age");
    const maxHosts = positiveInt(opts["max-hosts"], "max-hosts", 500);
    const concurrency = positiveInt(opts.concurrency, "concurrency", 4);
    const timeoutMs = positiveInt(opts.timeout, "timeout", 300) * 1000;
    const failOnError = !opts["no-fail-on-error"];
    const isPrivate = opts.private ? true : opts.public ? false : undefined;

    const client = createClient({
      apiKey: opts["api-key"] || env.LINKTHREATSCAN_API_KEY,
      apiUrl: opts["api-url"] || env.LINKTHREATSCAN_API_URL || DEFAULT_API_URL,
      fetch: io.fetch,
      timeoutMs,
      ...io.clientOptions,
    });

    const patterns = command === "scan" ? (rest.length ? rest : ["."]) : [];
    const urls = [...(command === "check" ? rest : []), ...(opts.url ?? [])];
    const { groups, filesRead, unmatched, invalidUrls } = await findLinks({
      patterns,
      urls,
      excludeHosts: opts["exclude-host"] ?? [],
      cwd,
    });
    for (const p of unmatched) warn(`linkthreatscan: nothing matches '${p}'`);
    for (const u of invalidUrls) warn(`linkthreatscan: not a public http(s) URL, skipped: '${u}'`);
    if (groups.length === 0) {
      if (invalidUrls.length && command === "check") return EXIT.ERROR;
      warn(`linkthreatscan: no links to check${patterns.length ? ` in ${filesRead} file${filesRead === 1 ? "" : "s"}` : ""}.`);
      return EXIT.CLEAN;
    }
    if (groups.length > maxHosts) {
      throw new UsageError(
        `Found links to ${groups.length} hosts, more than --max-hosts (${maxHosts}). Each new host is a scan on your organization's quota.`,
      );
    }

    const ci = detectCiContext(env);
    const results = await checkHosts(client, groups, {
      concurrency,
      ci,
      maxAge,
      minScore,
      private: isPrivate,
      batchId: randomUUID(),
      onResult: opts.json ? undefined : (r) => print(formatLine(r)),
    });
    const summary = summarize(results);
    const report = buildReport({ apiUrl: client.apiUrl, ci, minScore, maxAge, summary, results: [...results].sort(bySeverity) });

    if (opts.report) await writeFile(opts.report, JSON.stringify(report, null, 2) + "\n");
    if (opts.json) {
      print(JSON.stringify(report, null, 2));
    } else {
      print();
      print(
        `${summary.links} link${summary.links === 1 ? "" : "s"} to ${summary.hosts} host${summary.hosts === 1 ? "" : "s"}: ` +
          `${summary.clean} clean, ${summary.malicious} malicious` +
          (summary.unreachable ? `, ${summary.unreachable} unreachable` : "") +
          (summary.errors ? `, ${summary.errors} failed` : "") +
          (summary.reused ? ` (${summary.reused} reused)` : ""),
      );
    }

    if (summary.malicious) return EXIT.MALICIOUS;
    if (summary.errors && failOnError) return EXIT.ERROR;
    if (summary.unreachable && opts["fail-on-unreachable"]) return EXIT.ERROR;
    return EXIT.CLEAN;
  } catch (e) {
    warn(`linkthreatscan: ${e.message}`);
    return EXIT.ERROR;
  }
}
