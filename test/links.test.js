import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractLinks, groupByHost, hostMatcher, ipLink, isScannableHost, trimLink } from "../src/links.js";
import { findLinks } from "../src/find.js";

const urls = (text) => extractLinks(text).map((l) => l.url);

test("links are cut out of prose, Markdown, HTML, code and config", () => {
  assert.deepEqual(urls("See https://docs.rs/tokio. Then (https://crates.io/x) and https://a.io/b, done!"), [
    "https://docs.rs/tokio",
    "https://crates.io/x",
    "https://a.io/b",
  ]);
  assert.deepEqual(urls("[docs](https://en.wikipedia.org/wiki/Foo_(bar)) **https://bold.dev/**"), [
    "https://en.wikipedia.org/wiki/Foo_(bar)",
    "https://bold.dev/",
  ]);
  assert.deepEqual(urls(`<a href="https://cdn.site.com/a.js?x=1&amp;y=2">x</a> <img src='http://img.net/p.png'>`), [
    "https://cdn.site.com/a.js?x=1&amp;y=2",
    "http://img.net/p.png",
  ]);
  assert.deepEqual(urls('const u = "https://api.stripe.com/v1";\nfetch(`https://hooks.slack.com/x`)'), [
    "https://api.stripe.com/v1",
    "https://hooks.slack.com/x",
  ]);
  assert.deepEqual(urls('{"homepage":"https://pkg.dev\\nnext"}'), ["https://pkg.dev"], "a JSON escape ends the link");
  assert.equal(trimLink("https://a.com/x&quot;rest"), "https://a.com/x");
});

test("each link knows its line and column", () => {
  const [a, b] = extractLinks("first line\n  go to https://one.com/x and\nhttps://two.com");
  assert.deepEqual([a.line, a.column, a.origin], [2, 9, "https://one.com/"]);
  assert.deepEqual([b.line, b.column, b.host], [3, 1, "two.com"]);
});

test("hosts that cannot be on the public internet, namespaces and placeholders are skipped", () => {
  const skipped = [
    "http://localhost:3000/x",
    "http://127.0.0.1/",
    "http://10.0.0.8/",
    "http://192.168.1.1/",
    "http://172.20.0.1/",
    "http://169.254.169.254/latest/meta-data",
    "http://[::1]:8080/",
    "https://intranet/",
    "https://app.local/",
    "https://svc.internal/",
    "https://foo.test/",
    "https://example.com/",
    "https://www.example.org/x",
    "http://www.w3.org/2000/svg",
    "http://schemas.xmlsoap.org/soap/envelope/",
    "https://${HOST}/api",
    "https://{{ domain }}/x",
    "https://host_with_underscore.com/",
  ];
  for (const u of skipped) assert.deepEqual(urls(u), [], u);
  assert.deepEqual(urls("http://45.33.32.156/payload.sh"), ["http://45.33.32.156/payload.sh"], "public IPs are scanned");
  assert.equal(isScannableHost("xn--80ak6aa92e.com"), true, "IDNs, punycoded");
  assert.equal(isScannableHost("example.co"), true);
});

test("links group by host, scanning the https origin when there is one", () => {
  const occ = (url, file, line) => {
    const u = new URL(url);
    return { url, host: u.hostname, origin: `${u.origin}/`, file, line, column: 1 };
  };
  const groups = groupByHost(
    [
      occ("http://site.com/a", "a.md", 1),
      occ("https://site.com/b?token=secret", "b.md", 2),
      occ("https://cdn.other.net/x", "a.md", 3),
      occ("https://skip.corp.net/", "a.md", 4),
    ],
    hostMatcher(["corp.net"]),
  );
  assert.deepEqual(
    groups.map((g) => [g.host, g.url, g.occurrences.length]),
    [
      ["cdn.other.net", "https://cdn.other.net/", 1],
      ["site.com", "https://site.com/", 2],
    ],
  );
});

test("an IP is grouped by port", () => {
  assert.deepEqual(ipLink("http://8.8.8.8"), { port: null, bare: true });
  assert.deepEqual(ipLink("http://8.8.8.8/"), { port: null, bare: true });
  assert.deepEqual(ipLink("http://8.8.8.8:80/"), { port: "80", bare: true }, "a typed :80 is a port");
  assert.deepEqual(ipLink("http://8.8.8.8/stuff/whatever"), { port: null, bare: false });
  assert.deepEqual(ipLink("http://8.8.8.8/?q=1"), { port: null, bare: false });
  assert.equal(ipLink("https://site.com/"), null);
  const occ = (url, file, line) => {
    const u = new URL(url);
    return { url, host: u.hostname, origin: `${u.origin}/`, file, line, column: 1 };
  };

  const groups = groupByHost([
    occ("http://8.8.8.8", "a.md", 1),
    occ("http://8.8.8.8:8000/login", "a.md", 2),
    occ("https://8.8.8.8:8443/", "a.md", 3),
    occ("http://8.8.8.8:80/", "a.md", 4),
    occ("http://1.1.1.1/", "b.md", 1),
    occ("http://1.1.1.1/payload.bin", "b.md", 2),
    occ("https://site.com/x", "b.md", 3),
  ]);
  assert.deepEqual(
    groups.map((g) => [g.host, g.url, g.occurrences.length]),
    [
      ["1.1.1.1", "http://1.1.1.1/", 2],
      ["8.8.8.8", "http://8.8.8.8/", 1],
      ["8.8.8.8:80", "http://8.8.8.8:80/", 1],
      ["8.8.8.8:8000", "http://8.8.8.8:8000/", 1],
      ["8.8.8.8:8443", "https://8.8.8.8:8443/", 1],
      ["site.com", "https://site.com/", 1],
    ],
  );
});

test("exclude-hosts takes hosts with their subdomains, and globs", () => {
  const m = hostMatcher(["github.com", "*.cdn.acme.io", "https://docs.rs/whatever"]);
  assert.ok(m("github.com") && m("raw.github.com"));
  assert.ok(!m("notgithub.com"));
  assert.ok(m("eu.cdn.acme.io") && !m("cdn.acme.io") && !m("a.b.cdn.acme.io"));
  assert.ok(m("docs.rs"));
});

test("a repository's text files are read; binaries, lockfiles, maps and node_modules are not", async () => {
  const root = await mkdtemp(join(tmpdir(), "lts-find-"));
  const files = {
    "README.md": "Download from https://good.dev/get and http://malware-host.com/x\n",
    "src/app.js": 'fetch("https://api.good.dev/v1")',
    "package-lock.json": '{"resolved":"https://registry.npmjs.org/x"}',
    "dist/app.js.map": '{"sources":["https://sourcemap.dev/"]}',
    "node_modules/dep/index.js": "https://dependency.dev/",
    "logo.png": "https://in-a-png.dev/",
    "blob.dat": "https://binary.dev/\u0000\u0001",
  };
  for (const [name, text] of Object.entries(files)) {
    await mkdir(join(root, name, ".."), { recursive: true });
    await writeFile(join(root, name), text);
  }
  const r = await findLinks({ patterns: ["."], urls: ["https://extra.dev/page", "not a url", "http://localhost/"], cwd: root });
  assert.deepEqual(
    r.groups.map((g) => g.host),
    ["api.good.dev", "extra.dev", "good.dev", "malware-host.com"],
  );
  assert.deepEqual(r.invalidUrls, ["not a url", "http://localhost/"]);
  const readme = r.groups.find((g) => g.host === "good.dev").occurrences[0];
  assert.deepEqual(readme, { file: "README.md", line: 1, column: 15, url: "https://good.dev/get" });
});
