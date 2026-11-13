# LinkThreatScan — link check for CI/CD

Fail a build when your repository links to a malicious site. Every link in
your code, docs and config is found, grouped by host, and scored by
[LinkThreatScan](https://linkthreatscan.com). A host scoring below your
organization's threshold fails the step, with an annotation on each line that
links to it.

- **For organizations.** It takes an organization's API key, on a subscribed
  organization. Personal keys are refused (`403 organization_required`).
- **Only origins leave the runner.** Each host is checked once, as
  `https://host/`. Paths and query strings, which can carry tokens, are never
  sent.
- **IP addresses by port.** `http://203.0.113.7:8000/` and `:8443` are checked
  separately. Links to an IP without a port that are only the IP
  (`http://203.0.113.7/`) are reported unreachable without a scan; one with a
  path is scanned.
- **Configured on linkthreatscan.com, not in the workflow.** Your
  organization's **CI/CD** page sets the minimum score (3,000 to start) and
  how long a result is reused (24 hours to start), and lists the hosts of each
  repository's latest run so you can switch any of them off — later runs skip
  it.
- **Cheap on re-runs.** A host your organization checked within the reuse
  window is answered from that result and costs no scan. Every other host is
  one full scan on your organization's daily volume.
- **No dependencies.** Node 20+ only.

Every run shows on your organization's **CI/CD** page on
linkthreatscan.com, by repository and run.

## GitHub Action

1. Create an API key on your organization's **API keys** page.
2. Add it to the repository as the Actions secret `LINKTHREATSCAN_API_KEY`
   (Settings → Secrets and variables → Actions).
3. Add a workflow:

```yaml
name: Link check

on:
  push:
    branches: [main]
  pull_request:

jobs:
  links:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: decentralisoft/link-scanner-cicd-action@v1
        id: links
        with:
          api-key: ${{ secrets.LINKTHREATSCAN_API_KEY }}
```

| Input | Default | |
|---|---|---|
| `api-key` | — | **Required.** An organization's key. Store it as a secret. |
| `files` | `.` | Paths, directories or globs to read, one per line. `!` excludes. |
| `urls` | — | More URLs to check, one per line. |
| `exclude-hosts` | — | Hosts to skip, one per line or comma-separated. `example.org` also skips its subdomains. `*.cdn.example.org` is a glob. |
| `fail-on-malicious` | `true` | Fail the step when a malicious link is found. |
| `fail-on-unreachable` | `false` | Fail when a host cannot be scanned (it does not resolve, or not to a public address). |
| `fail-on-error` | `true` | Fail when a host could not be checked (the API refused or could not be reached). |
| `if-no-links-found` | `ignore` | `error`, `warn` or `ignore`. |
| `max-hosts` | `500` | Refuse to start above this many hosts, before spending any scan. |
| `concurrency` | `4` | Hosts checked in parallel. |
| `timeout` | `300` | Seconds to wait for one host's verdict. |
| `private` | — | `true` or `false`: whether new scans' reports are private to your organization. The default is the organization's setting. |
| `api-url` | `https://linkthreatscan.com` | |

| Output | |
|---|---|
| `result` | `clean`, `malicious`, `error`, or `none` when there was nothing to check |
| `links`, `hosts`, `malicious`, `unreachable`, `errors`, `skipped` | Counts (`skipped`: hosts switched off for the repository on linkthreatscan.com) |
| `report` | Path to the JSON report: every host's verdict, score, threats and report link, and every file and line that links to it |

The job summary lists every host. To keep the report, see
[`examples/link-check.yml`](examples/link-check.yml).

> **Upgrading from 1.0:** `min-score` and `max-age` are no longer inputs. Set
> them on your organization's CI/CD page instead; a workflow that still passes
> them gets a warning and the organization's values apply.

### What is read, and what is skipped

- `.git` and `node_modules` are never read. Lockfiles (`package-lock.json`,
  `yarn.lock`, `Cargo.lock`, `go.sum`, …), source maps, binary files and
  files over 5 MB are skipped.
- Some hosts are never checked: anything that can't be on the public internet
  (`localhost`, private and reserved IPs, single-label names, `.local`,
  `.test`, `.example`, `.invalid`, `.internal`), the `example.com/.net/.org`
  documentation domains, XML namespace URIs (`www.w3.org/2000/svg`, …), and
  template placeholders such as `https://${HOST}/`.

## GitLab CI and the command line

```yaml
link-check:
  image: node:22
  script:
    - npx linkthreatscan scan
```

Set `LINKTHREATSCAN_API_KEY` as a masked CI/CD variable. On GitLab CI, checks
carry the project, commit and pipeline.

```bash
export LINKTHREATSCAN_API_KEY=lts_...

npx linkthreatscan scan                          # every file under .
npx linkthreatscan scan docs/ "src/**/*.ts" '!docs/archive/**'
npx linkthreatscan check https://cdn.example.org/lib.js
npx linkthreatscan scan --json --report links.json
```

```
  clean        docs.rs  8,912  (reused)
✗ MALICIOUS    malware-host.com  640  docs/install.md:3 (+2)  listed by linkThreatScan
               https://linkthreatscan.com/s/3f0c…
  unreachable  old-mirror.net  Hostname does not resolve: old-mirror.net  README.md:41

5 links to 3 hosts: 1 clean, 1 malicious, 1 unreachable (1 reused)
```

| Exit code | Meaning |
|---|---|
| `0` | No malicious link (hosts that cannot be scanned are reported, not failed) |
| `1` | A malicious link was found |
| `2` | A check failed, the API refused the request, or bad usage |

Options: `--url <url>` and `--exclude-host <host>` (both repeatable),
`--max-hosts`, `--private` / `--public`, `--json`,
`--report <file>`, `--concurrency`, `--timeout`, `--fail-on-unreachable`,
`--no-fail-on-error`, `--api-url`. Prefer the `LINKTHREATSCAN_API_KEY`
variable to `--api-key`, which shows up in process lists.

## Library

```js
import { createClient, findLinks, checkHosts, summarize } from "linkthreatscan";

const client = createClient({ apiKey: process.env.LINKTHREATSCAN_API_KEY });
const { groups } = await findLinks({ patterns: ["docs"], cwd: process.cwd() });
const results = await checkHosts(client, groups);
console.log(summarize(results)); // { hosts, links, clean, malicious, unreachable, errors, skipped, reused, result }
```

## API

The action calls `POST /api/v1/ci/check` once per host. The full reference
is at <https://linkthreatscan.com/docs/api/ci>.

## Development

```bash
npm test     # node --test, against a local mock of the API
```
