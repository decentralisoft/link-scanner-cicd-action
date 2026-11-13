// Find the http(s) links in a repository's files and group them by host.
//
// A link is judged by its host: every link to the same host shares one scan,
// and only the host's origin (`https://host/`) is ever sent to the API — never
// a path or a query string, which can carry tokens.
//
// Skipped on purpose:
//   - hosts that cannot be on the public internet: localhost, private and
//     reserved IP addresses, single-label names, reserved suffixes (.local,
//     .test, .example, .invalid, .internal, .localhost, .home.arpa) and the
//     example.com/.net/.org documentation domains;
//   - XML and schema namespace URIs (www.w3.org/2000/svg and the like), which
//     are identifiers, not links anyone follows;
//   - template placeholders (`https://${host}/`, `https://{{ domain }}`),
//     which never parse into a host;
//   - binary files, lockfiles and source maps, and files over 5 MB.

import { open, stat } from "node:fs/promises";
import { extname } from "node:path";

/** Files larger than this are not read. */
export const MAX_FILE_BYTES = 5 * 1024 * 1024;

/** Excluded unless the workflow names them: generated, and full of registry URLs. */
export const DEFAULT_EXCLUDES = [
  "!**/package-lock.json",
  "!**/npm-shrinkwrap.json",
  "!**/yarn.lock",
  "!**/pnpm-lock.yaml",
  "!**/bun.lock",
  "!**/Cargo.lock",
  "!**/Gemfile.lock",
  "!**/composer.lock",
  "!**/poetry.lock",
  "!**/uv.lock",
  "!**/Pipfile.lock",
  "!**/go.sum",
  "!**/*.map",
];

const BINARY_EXTENSIONS = new Set(
  (
    ".png .jpg .jpeg .gif .webp .avif .ico .bmp .tif .tiff .psd .heic " +
    ".woff .woff2 .ttf .otf .eot " +
    ".mp3 .mp4 .m4a .mov .avi .mkv .webm .wav .flac .ogg " +
    ".zip .gz .tgz .bz2 .xz .7z .rar .tar .jar .war .whl .nupkg " +
    ".exe .dll .so .dylib .bin .o .a .class .pyc .wasm .node " +
    ".pdf .doc .docx .xls .xlsx .ppt .pptx .sqlite .db"
  ).split(" "),
);

/** Namespace and schema hosts: their URIs identify a vocabulary, nobody visits them. */
export const NAMESPACE_HOSTS = new Set([
  "www.w3.org",
  "w3.org",
  "schemas.xmlsoap.org",
  "schemas.microsoft.com",
  "schemas.openxmlformats.org",
  "schemas.android.com",
  "purl.org",
  "xmlns.com",
  "ns.adobe.com",
  "json-schema.org",
]);

const RESERVED_SUFFIXES = [".localhost", ".local", ".test", ".example", ".invalid", ".internal", ".home.arpa", ".lan"];
const DOCUMENTATION_DOMAINS = ["example.com", "example.net", "example.org"];

// Stops at whitespace, quotes, angle brackets, backslashes (JSON escapes),
// backticks, braces and square brackets — every character that ends a link in
// prose, markup, code or config.
const URL_RE = /\bhttps?:\/\/[^\s<>"'`\\^{}|[\]]+/gi;
const TRAILING = /[.,;:!?*~]+$/;
const ENTITY = /&(?:quot|gt|lt|apos|#\d+|#x[0-9a-f]+);.*$/i;

/** Cut what prose, Markdown and HTML wrap around a link. */
export function trimLink(raw) {
  let s = raw.replace(ENTITY, "");
  for (;;) {
    const before = s;
    s = s.replace(TRAILING, "");
    // A closing parenthesis belongs to the link only when it closes one the
    // link opened: Wikipedia's "Foo_(bar)" keeps it, "(see https://a.com)" loses it.
    while (s.endsWith(")") && count(s, "(") < count(s, ")")) s = s.slice(0, -1);
    if (s === before) return s;
  }
}

const count = (s, c) => s.split(c).length - 1;

function isPrivateIPv4(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

/**
 * Whether a link's host is worth scanning: on the public internet, and not a
 * namespace identifier.
 * @param {string} host a lower-case, punycoded hostname, as `URL` gives it
 */
export function isScannableHost(host) {
  if (!host) return false;
  if (host.startsWith("[")) return false; // IPv6 literals: not worth guessing which are public
  const privateIp = isPrivateIPv4(host);
  if (privateIp !== null) return !privateIp;
  if (!/^[a-z0-9.-]+$/.test(host) || !host.includes(".")) return false;
  const tld = host.slice(host.lastIndexOf(".") + 1);
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) return false;
  if (host === "localhost" || RESERVED_SUFFIXES.some((s) => host.endsWith(s))) return false;
  if (DOCUMENTATION_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`))) return false;
  return !NAMESPACE_HOSTS.has(host);
}

/**
 * A matcher for the `exclude-hosts` input: `example.org` matches the host and
 * its subdomains, `*.cdn.example.org` is a glob over the host.
 * @param {string[]} entries
 */
export function hostMatcher(entries) {
  const rules = entries
    .map((e) => e.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, ""))
    .filter(Boolean)
    .map((e) => {
      if (e.includes("*")) {
        const re = new RegExp("^" + e.replace(/[.+?^$()|[\]\\]/g, "\\$&").replace(/\*/g, "[^.]*") + "$");
        return (h) => re.test(h);
      }
      return (h) => h === e || h.endsWith(`.${e}`);
    });
  return (host) => rules.some((r) => r(host));
}

/**
 * Every link in a text, with where it was found.
 * @returns {{ url: string, host: string, origin: string, line: number, column: number }[]}
 */
export function extractLinks(text) {
  const found = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const m of lines[i].matchAll(URL_RE)) {
      const url = trimLink(m[0]);
      let parsed;
      try {
        parsed = new URL(url);
      } catch {
        continue;
      }
      if (!isScannableHost(parsed.hostname)) continue;
      found.push({ url, host: parsed.hostname, origin: `${parsed.origin}/`, line: i + 1, column: m.index + 1 });
    }
  }
  return found;
}

/** Read a file as text, or `null` for a binary or oversized one. */
export async function readText(path) {
  if (BINARY_EXTENSIONS.has(extname(path).toLowerCase())) return null;
  const info = await stat(path);
  if (info.size === 0 || info.size > MAX_FILE_BYTES) return null;
  const handle = await open(path, "r");
  try {
    const buf = await handle.readFile();
    // A NUL byte early on is the usual sign of a binary file.
    if (buf.subarray(0, 8000).includes(0)) return null;
    return buf.toString("utf8");
  } finally {
    await handle.close();
  }
}

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Whether a URL's hostname is an IP address (IPv6 comes bracketed). */
export function isIpHost(host) {
  return IPV4_RE.test(host) || host.startsWith("[");
}

/**
 * How an IP link is written: its port as typed — `:80` on http counts, though
 * `URL` drops it — and whether it is only the IP, with nothing after it but a
 * `/`. `null` for a link whose host is a name.
 * @returns {{ port: string|null, bare: boolean } | null}
 */
export function ipLink(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return null;
  }
  if (!isIpHost(parsed.hostname)) return null;
  const rest = raw.includes("://") ? raw.slice(raw.indexOf("://") + 3) : raw;
  const authority = rest.split(/[/?#]/, 1)[0];
  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  const afterHost = hostPort.includes("]") ? hostPort.slice(hostPort.lastIndexOf("]") + 1) : hostPort;
  const port = afterHost.includes(":") ? afterHost.slice(afterHost.indexOf(":") + 1) || null : null;
  const bare = (parsed.pathname === "/" || parsed.pathname === "") && !parsed.search && !parsed.hash && !/[?#]/.test(rest);
  return { port, bare };
}

/**
 * Group occurrences by host. The scanned URL is the host's https origin when
 * any link to it uses https, else its http origin.
 *
 * An IP address is grouped by port instead: `1.2.3.4:8000` and `1.2.3.4:8443`
 * are different services, each with its own verdict. Its links without a port
 * are one group, sent with `bareIp: true` when every one of them is only the
 * IP (`http://1.2.3.4/`) — the API answers that unreachable without a scan —
 * and `false` when any has a path, which is scanned. A name's group has no
 * `bareIp`.
 * @param {{ url: string, host: string, origin: string, file: string, line?: number, column?: number }[]} occurrences
 * @param {(host: string) => boolean} [excluded]
 * @returns {{ host: string, url: string, bareIp?: boolean, occurrences: object[] }[]} sorted by host
 */
export function groupByHost(occurrences, excluded = () => false) {
  const groups = new Map();
  for (const o of occurrences) {
    if (excluded(o.host)) continue;
    const ip = ipLink(o.url);
    const key = ip?.port ? `${o.host}:${ip.port}` : o.host;
    // With the port as typed: `http://1.2.3.4:80/` must not read as bare.
    const origin = ip?.port ? `${new URL(o.url).protocol}//${key}/` : o.origin;
    let g = groups.get(key);
    if (!g) {
      g = { host: key, url: origin, ...(ip ? { bareIp: !ip.port } : {}), occurrences: [] };
      groups.set(key, g);
    }
    if (g.url.startsWith("http:") && origin.startsWith("https:")) g.url = origin;
    if (ip && !ip.bare) g.bareIp = false;
    const { file, line, column, url } = o;
    g.occurrences.push({ file, ...(line ? { line, column } : {}), url });
  }
  return [...groups.values()].sort((a, b) => a.host.localeCompare(b.host));
}

/**
 * Collect the links of `files` (absolute paths, labelled by `label`) and of
 * explicit `urls`.
 * @returns {Promise<{ occurrences: object[], filesRead: number, invalidUrls: string[] }>}
 */
export async function collectLinks(files, { urls = [], label = (f) => f } = {}) {
  const occurrences = [];
  let filesRead = 0;
  for (const file of files) {
    let text;
    try {
      text = await readText(file);
    } catch {
      continue; // vanished or unreadable: nothing to scan in it
    }
    if (text === null) continue;
    filesRead++;
    for (const link of extractLinks(text)) occurrences.push({ ...link, file: label(file) });
  }
  const invalidUrls = [];
  for (const raw of urls) {
    let parsed;
    try {
      parsed = new URL(raw.trim());
    } catch {
      invalidUrls.push(raw);
      continue;
    }
    if (!["http:", "https:"].includes(parsed.protocol) || !isScannableHost(parsed.hostname)) {
      invalidUrls.push(raw);
      continue;
    }
    occurrences.push({ url: raw.trim(), host: parsed.hostname, origin: `${parsed.origin}/`, file: "(urls)" });
  }
  return { occurrences, filesRead, invalidUrls };
}
