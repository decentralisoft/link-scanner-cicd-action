// A small client for the LinkThreatScan CI endpoint (`POST /api/v1/ci/check`).
// No dependencies: Node 20+ ships fetch.

import { VERSION } from "./version.js";

export const DEFAULT_API_URL = "https://linkthreatscan.com";

/** An answer from the API that was not a success. */
export class ApiError extends Error {
  constructor(message, { status = null, retryAfter = null, code = null, body = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.retryAfter = retryAfter;
    this.code = code;
    this.body = body;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function retryAfterSeconds(res) {
  const raw = res.headers.get("retry-after");
  const n = raw == null ? NaN : Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

async function readJson(res) {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * @param {object} options
 * @param {string} options.apiKey   an organization's API key
 * @param {string} [options.apiUrl] defaults to https://linkthreatscan.com
 * @param {typeof fetch} [options.fetch]
 * @param {number} [options.timeoutMs] per request; a fresh full scan takes up to a minute or two
 * @param {number} [options.maxWaits] how many 429/503 answers with Retry-After to wait out per call
 * @param {number[]} [options.networkRetryDelaysMs] pauses before retrying a call whose connection failed
 */
export function createClient({
  apiKey,
  apiUrl = DEFAULT_API_URL,
  fetch: fetchImpl = globalThis.fetch,
  timeoutMs = 300_000,
  maxWaits = 8,
  networkRetryDelaysMs = [10_000, 30_000],
} = {}) {
  if (!apiKey) {
    throw new ApiError(
      "No API key. Set LINKTHREATSCAN_API_KEY (or pass --api-key) to one of your organization's keys, from its API keys page on https://linkthreatscan.com/dashboard/organizations",
    );
  }
  const base = apiUrl.replace(/\/+$/, "");
  const userAgent = `linkthreatscan-cli/${VERSION} node/${process.versions.node}`;

  /**
   * One API call.
   *
   * - A per-minute rate limit (429 with Retry-After) and a busy scanner (503
   *   with Retry-After) are waited out: neither costs anything.
   * - A daily-quota refusal (429 without Retry-After) is not: waiting would
   *   not help.
   * - A dropped connection is retried after a pause. The server may well have
   *   finished the scan; with `maxAge` above 0 the retry then reuses it for
   *   free instead of scanning again.
   */
  async function call(method, path, body) {
    let waits = 0;
    let networkFailures = 0;
    for (;;) {
      let res;
      try {
        res = await fetchImpl(base + path, {
          method,
          headers: {
            authorization: `Bearer ${apiKey}`,
            "user-agent": userAgent,
            accept: "application/json",
            ...(body === undefined ? {} : { "content-type": "application/json" }),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (err) {
        if (networkFailures < networkRetryDelaysMs.length) {
          await sleep(networkRetryDelaysMs[networkFailures++]);
          continue;
        }
        const reason = err.name === "TimeoutError" ? `no answer within ${Math.round(timeoutMs / 1000)} s` : err.cause?.code || err.message;
        throw new ApiError(`Could not reach ${base}: ${reason}`, { code: "network" });
      }

      const data = await readJson(res);
      if (res.ok) return data;

      const retryAfter = retryAfterSeconds(res);
      if ((res.status === 429 || res.status === 503) && retryAfter != null && retryAfter <= 60 && waits < maxWaits) {
        waits++;
        await sleep(Math.max(retryAfter, 1) * 1000);
        continue;
      }
      throw new ApiError(data?.error || `HTTP ${res.status} from ${method} ${path}`, {
        status: res.status,
        retryAfter,
        code: data?.code ?? null,
        body: data,
      });
    }
  }

  return {
    apiUrl: base,

    /**
     * Check one host. `url` should be the host's origin (`https://host/`).
     * Resolves to the verdict; throws ApiError otherwise. An unscannable host
     * (does not resolve, not public) is a 422 with code `unreachable`.
     *
     * @param {object} req
     * @param {string} req.url
     * @param {object|null} [req.ci]     the pipeline context (ci.js)
     * @param {boolean} [req.private]    whether a fresh scan's report is private; default: the organization's
     * @param {string} [req.batchId]     groups one run's checks on the CI/CD page
     * @param {number} [req.links]       how many links point at the host (shown on the CI/CD page)
     * @param {boolean} [req.bareIp]     an IP's links without a port: true when every one is only the IP
     */
    checkLink: ({ url, ci, private: isPrivate, batchId, links, bareIp }) =>
      call("POST", "/api/v1/ci/check", {
        url,
        ...(ci ? { ci } : {}),
        ...(isPrivate !== undefined ? { private: isPrivate } : {}),
        ...(batchId ? { batchId } : {}),
        ...(links ? { links } : {}),
        ...(typeof bareIp === "boolean" ? { bareIp } : {}),
      }),
  };
}
