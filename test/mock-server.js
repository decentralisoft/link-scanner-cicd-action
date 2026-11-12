// A stand-in for the LinkThreatScan CI endpoint, enough to drive the CLI and
// the Action through every path: clean and malicious hosts, an unscannable
// host, reuse of a recent result, rate limiting, a busy scanner, and refused
// keys.
//
// Keys: org-key (a subscribed organization), personal-key (a person's key),
// unpaid-key (an organization without a subscription), anything else invalid.
// Hosts: anything with "malware" in it scores 500 and is listed; anything
// with "dead" in it does not resolve; everything else scores 8,200.
//
// `org` holds what the organization set on its CI/CD page: the threshold, the
// reuse window, and "owner/repo host" entries switched off. Like the real
// server, the mock ignores any minScore / maxAge in the body.

import { createServer } from "node:http";
import { randomUUID } from "node:crypto";

export async function startMockServer({ rateLimitFirstCheck = false, busyFirstCheck = false } = {}) {
  const calls = [];
  const received = []; // every request body
  const recent = new Map(); // host → the last fresh result
  const org = { minScore: 3000, maxAge: 86400, disabled: new Set() };
  let rateLimited = !rateLimitFirstCheck;
  let busy = !busyFirstCheck;

  const send = (res, status, body, headers = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(body));
  };
  const readBody = (req) =>
    new Promise((resolve) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://x");
    calls.push(`${req.method} ${url.pathname}`);
    const raw = await readBody(req);
    const auth = req.headers.authorization;

    if (url.pathname !== "/api/v1/ci/check" || req.method !== "POST") return send(res, 404, { error: "Not found" });
    if (auth === "Bearer personal-key") {
      return send(res, 403, {
        error: "CI/CD link checks are for organizations: use one of your organization's API keys.",
        code: "organization_required",
      });
    }
    if (auth === "Bearer unpaid-key") {
      return send(res, 402, { error: "This organization's API access requires an active subscription." });
    }
    if (auth !== "Bearer org-key") return send(res, 401, { error: "Invalid or revoked API key." });
    if (!rateLimited) {
      rateLimited = true;
      return send(res, 429, { error: "Rate limit exceeded." }, { "retry-after": "1" });
    }
    if (!busy) {
      busy = true;
      return send(res, 503, { error: "The scanner is busy. Retry shortly." }, { "retry-after": "1" });
    }

    const body = JSON.parse(raw);
    received.push(body);
    const target = new URL(body.url);
    const host = target.hostname;
    const { minScore, maxAge } = org;
    if (org.disabled.has(`${body.ci?.repository} ${host}`)) {
      return send(res, 200, { host, url: body.url, verdict: "skipped", score: null, risk: null, minScore, threats: [], scanId: null, reportUrl: null, scannedAt: null, reused: false });
    }

    if (host.includes("dead")) {
      return send(res, 422, { error: `Hostname does not resolve: ${host}`, code: "unreachable", host });
    }
    const previous = recent.get(host);
    if (previous && maxAge > 0) {
      return send(res, 200, { ...previous, minScore, verdict: previous.score < minScore ? "failed" : "passed", reused: true });
    }
    const malware = host.includes("malware");
    const scanId = randomUUID();
    const result = {
      host,
      url: body.url,
      score: malware ? 500 : 8200,
      risk: malware ? "high" : "low",
      threats: malware ? ["linkThreatScan", "googleSafeBrowsing"] : [],
      scanId,
      reportUrl: `${base}/s/${scanId}`,
      scannedAt: new Date().toISOString(),
    };
    recent.set(host, result);
    return send(res, 200, { ...result, minScore, verdict: result.score < minScore ? "failed" : "passed", reused: false });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    url: base,
    calls,
    received,
    recent,
    org,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
