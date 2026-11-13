// Check every host a repository links to, a few at a time, and add up the
// verdicts. One host is one call: the server reuses the organization's recent
// CI result for it when there is one, and runs a full scan otherwise.
//
// The threshold, the reuse window and the hosts to skip are the
// organization's, set on its CI/CD page at linkthreatscan.com: the server
// judges each host and says so in `verdict`.

import { ApiError } from "./client.js";

export const Status = Object.freeze({
  /** Scored at or above the threshold. */
  CLEAN: "CLEAN",
  /** Scored below the threshold — or listed by a threat feed, which puts it far below. */
  MALICIOUS: "MALICIOUS",
  /** The host could not be scanned: it does not resolve, or not to a public address. */
  UNREACHABLE: "UNREACHABLE",
  /** The check itself failed: the API refused it or could not be reached. */
  ERROR: "ERROR",
  /** Switched off for this repository on linkthreatscan.com: not scanned. */
  SKIPPED: "SKIPPED",
});

// The three below are kept for library users. The Action and the CLI no
// longer read a threshold or a reuse window: the organization sets both.
export const DEFAULT_MIN_SCORE = 3000;
/** Reuse a CI result for the same host from the last 24 hours. */
export const DEFAULT_MAX_AGE_SECONDS = 24 * 3600;
export const MAX_MAX_AGE_SECONDS = 30 * 24 * 3600;

/**
 * "0", "3600", "90s", "45m", "24h", "7d" → seconds.
 * @returns {number}
 */
export function parseDuration(raw, name = "max-age") {
  const m = String(raw).trim().toLowerCase().match(/^(\d+)\s*([smhd]?)$/);
  if (!m) throw new Error(`${name} must be a duration such as 0, 3600, 45m, 24h or 7d.`);
  const seconds = Number(m[1]) * { "": 1, s: 1, m: 60, h: 3600, d: 86400 }[m[2]];
  if (seconds > MAX_MAX_AGE_SECONDS) throw new Error(`${name} can be at most 30 days.`);
  return seconds;
}

export function parseMinScore(raw, name = "min-score") {
  const n = Number(String(raw).trim());
  if (!Number.isInteger(n) || n < 0 || n > 10000) throw new Error(`${name} must be a whole number from 0 to 10000.`);
  return n;
}

/** Refusals that would repeat for every other host: stop early. */
function isFatal(err) {
  return (
    err instanceof ApiError &&
    (err.status === 401 ||
      err.status === 402 ||
      err.status === 403 ||
      (err.status === 429 && err.retryAfter == null) ||
      err.code === "network")
  );
}

/**
 * Check one host. Never throws: every outcome is a result object.
 * @param {{ host: string, url: string, occurrences: object[] }} group
 */
export async function checkHost(client, group, { ci, private: isPrivate, batchId } = {}) {
  const result = { host: group.host, url: group.url, status: Status.ERROR, occurrences: group.occurrences };
  try {
    const v = await client.checkLink({
      url: group.url,
      ci,
      private: isPrivate,
      batchId,
      links: group.occurrences.length,
    });
    const status = v.verdict === "skipped" ? Status.SKIPPED : v.verdict === "failed" ? Status.MALICIOUS : Status.CLEAN;
    return {
      ...result,
      status,
      minScore: typeof v.minScore === "number" ? v.minScore : null,
      score: v.score ?? null,
      risk: v.risk ?? null,
      threats: v.threats ?? [],
      scanId: v.scanId ?? null,
      reportUrl: v.reportUrl ?? null,
      reused: Boolean(v.reused),
      scannedAt: v.scannedAt ?? null,
    };
  } catch (err) {
    if (err instanceof ApiError && err.code === "unreachable") {
      return { ...result, status: Status.UNREACHABLE, error: err.message };
    }
    return { ...result, error: err.message, fatal: isFatal(err) };
  }
}

/**
 * Check many hosts with bounded concurrency. Stops starting new checks after
 * an error that would repeat for every host (bad key, personal key, no
 * subscription, quota spent, API unreachable).
 */
export async function checkHosts(client, groups, { concurrency = 4, onResult, ...opts } = {}) {
  const results = new Array(groups.length);
  let next = 0;
  let stopped = null;

  async function worker() {
    while (next < groups.length) {
      const i = next++;
      const g = groups[i];
      if (stopped) {
        results[i] = { host: g.host, url: g.url, status: Status.ERROR, occurrences: g.occurrences, error: `Not checked: ${stopped}` };
      } else {
        const r = await checkHost(client, g, opts);
        if (r.fatal) stopped = r.error;
        delete r.fatal;
        results[i] = r;
      }
      onResult?.(results[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, groups.length)) }, worker));
  return results;
}

export function summarize(results) {
  const count = (s) => results.filter((r) => r.status === s).length;
  const summary = {
    hosts: results.length,
    links: results.reduce((n, r) => n + r.occurrences.length, 0),
    clean: count(Status.CLEAN),
    malicious: count(Status.MALICIOUS),
    unreachable: count(Status.UNREACHABLE),
    errors: count(Status.ERROR),
    skipped: count(Status.SKIPPED),
    reused: results.filter((r) => r.reused).length,
  };
  summary.result = summary.malicious ? "malicious" : summary.errors ? "error" : "clean";
  return summary;
}

/** Most serious first, then by host. */
export function bySeverity(a, b) {
  const order = { MALICIOUS: 0, ERROR: 1, UNREACHABLE: 2, CLEAN: 3, SKIPPED: 4 };
  return order[a.status] - order[b.status] || a.host.localeCompare(b.host);
}

/** The organization's threshold, as the server reported it; null before any verdict. */
export function thresholdOf(results) {
  return results.find((r) => typeof r.minScore === "number")?.minScore ?? null;
}

/** "README.md:14" */
export const where = (o) => (o.line ? `${o.file}:${o.line}` : o.file);
