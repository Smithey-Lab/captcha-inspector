# CAPTCHA Inspector

[![CI](https://github.com/Smithey-Lab/captcha-inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/Smithey-Lab/captcha-inspector/actions)

A disposable, interactive browser for inspecting suspicious CAPTCHA pages, built by Smithey Lab. [Try the hosted tool](https://smitheylab.com/tools/captcha-inspector/).

The tool combines an Amazon Bedrock AgentCore browser, live remote viewing, page evidence and heuristic analysis. It includes clipboard isolation, a local copy/paste guard, view-only mode, and evidence exports. It does not solve CAPTCHAs automatically or determine whether a site is safe.

## Local development

Use Node.js 24 or newer:

```sh
npm ci
npm run ci
npm run dev
```

Open http://localhost:5173. The frontend endpoint is empty and disabled by default. Tests use fixtures and mocks; CI does not start AWS sessions or deploy infrastructure. A working remote browser requires your own backend; see [deployment](docs/deployment.md).

## Layout

- `src/`: standalone frontend and disabled example configuration.
- `backend/captcha/`: controller, analysis, error responses, audit events and browser policies.
- `backend/net-target.cjs`: public destination validation.
- `scripts/`: local builds and CloudFormation generation.

This repository contains this tool only. The parent website, login/admin portal, production configuration and user records are excluded.

## Limits and records

The viewer retains up to four selectable reports in tab memory, with capture timestamps and exports for the selected report. Clear individual reports or all local evidence, including the displayed screenshot. Clearing does not reset capture allowances, stop a session, or delete server audit records. Nothing is saved to browser storage.

Viewer connection begins while the browser starts. Manual actions wait for startup, duplicate reconnects are blocked, and Stop remains available during evidence capture. Offline lifecycle tests cover startup timing, stop during capture, stale responses and evidence clearing; these tests do not verify a real remote input channel.

The default limits are 60 seconds per session, one global admission lease, five starts per UTC day, 100 per UTC month and two starts per public network per day. Failed starts count. The optional trusted member integration can bypass the network allowance, but never the global limits. Additional evidence captures are limited and spaced apart.

Admission records and bounded audit events expire using DynamoDB TTL (deletion is asynchronous). Audit records retain the submitted origin and actor metadata, excluding paths, query names and values, fragments, raw IPs, stream URLs and page contents. Temporary session URLs are encrypted using the visitor's random session token; only its hash is stored. Ciphertext is cleared on stop or terminal startup failure. Public audit admission is limited to 1,000/day and 20/day per network; verified members have independent 100/day audit allowances. Paid browser start caps remain unchanged; new finite time reservations also apply. There is no admin log viewer in this standalone repository.

Rate limits reduce exposure; they are not a hard AWS billing ceiling. API requests, storage and other services can still incur charges. Browser isolation and destination checks are defensive layers, not a complete malware containment guarantee. Do not enter credentials or sensitive information into inspected pages.

See [feature research, detection coverage and finite member/admin controls](docs/features-and-detection.md) for this release and the roadmap.

## Contributing and security

Develop on feature branches and open pull requests into `dev`; promote releases into `main`. Both branches require the `Quality` check and resolved review conversations. Approval count is zero to allow a sole maintainer to merge their own passing PRs. See [CONTRIBUTING.md](CONTRIBUTING.md) and report vulnerabilities privately using [SECURITY.md](SECURITY.md).

CI runs lint, tests, a frontend build, a source publication pattern check and a production dependency audit. MIT applies to original code; see [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md) for third-party and branding boundaries.
