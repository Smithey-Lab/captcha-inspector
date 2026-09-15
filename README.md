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

The default limits are 60 seconds per session, one global admission lease, five starts per UTC day, 100 per UTC month and two starts per public network per day. Failed starts count. The optional trusted member integration can bypass the network allowance, but never the global limits. Additional evidence captures are limited and spaced apart.

Admission records and bounded audit events expire using DynamoDB TTL (deletion is asynchronous). Records can include submitted host/path, query parameter names and actor metadata. Query values, raw IPs, signed stream URLs and page contents are excluded from audit events. Session state briefly retains the submitted URL. Paths themselves can contain sensitive information. There is no admin log viewer in this standalone repository.

Rate limits reduce exposure; they are not a hard AWS billing ceiling. API requests, storage and other services can still incur charges. Browser isolation and destination checks are defensive layers, not a complete malware containment guarantee. Do not enter credentials or sensitive information into inspected pages.

## Contributing and security

Develop on feature branches and open pull requests into `dev`; promote releases into `main`. Both branches require the `Quality` check and resolved review conversations. Approval count is zero to allow a sole maintainer to merge their own passing PRs. See [CONTRIBUTING.md](CONTRIBUTING.md) and report vulnerabilities privately using [SECURITY.md](SECURITY.md).

CI runs lint, tests, a frontend build, a source publication pattern check and a production dependency audit. MIT applies to original code; see [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md) for third-party and branding boundaries.
