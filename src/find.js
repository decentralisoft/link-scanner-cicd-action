// From the workflow's (or the command line's) inputs to the hosts to check:
// expand the file patterns, read the links out of them, add the explicit
// URLs, drop excluded hosts, and group what is left by host.

import { relative } from "node:path";
import { expandPatterns } from "./files.js";
import { collectLinks, DEFAULT_EXCLUDES, groupByHost, hostMatcher } from "./links.js";

/**
 * @param {object} o
 * @param {string[]} o.patterns    paths, directories or globs; `!glob` excludes
 * @param {string[]} [o.urls]      URLs to check besides those found in files
 * @param {string[]} [o.excludeHosts]
 * @param {string} o.cwd
 */
export async function findLinks({ patterns, urls = [], excludeHosts = [], cwd }) {
  let files = [];
  let unmatched = [];
  if (patterns.length) {
    // Lockfiles and source maps are generated: never read, whatever the patterns say.
    ({ files, unmatched } = await expandPatterns([...DEFAULT_EXCLUDES, ...patterns], cwd));
  }
  const label = (f) => relative(cwd, f).split("\\").join("/") || f;
  const { occurrences, filesRead, invalidUrls } = await collectLinks(files, { urls, label });
  const groups = groupByHost(occurrences, hostMatcher(excludeHosts));
  return { groups, files, filesRead, unmatched, invalidUrls };
}

/** The JSON report both the Action and the CLI write. */
export function buildReport({ apiUrl, ci, minScore, summary, results }) {
  return {
    version: 1,
    apiUrl,
    ...(ci ? { ci } : {}),
    // The organization's threshold, as the server applied it.
    minScore: minScore ?? null,
    summary,
    results: results.map(({ occurrences, ...r }) => ({ ...r, links: occurrences })),
  };
}
