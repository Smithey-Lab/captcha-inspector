# Browser sandbox research and release coverage

Reviewed September 16, 2026. Detection describes observed evidence, never a guarantee that a page is safe or that every challenge was found. The tool does not solve or bypass CAPTCHAs.

## This release

- Provider evidence from bounded script URLs, iframe URLs and DOM widget markers: reCAPTCHA, hCaptcha, Turnstile, Cloudflare challenge platform, Arkose/FunCaptcha, GeeTest, Friendly Captcha, ALTCHA and AWS WAF.
- Recognition of invisible/provider-only widgets without requiring visible page text. HTTP challenge responses do not erase stronger observed threat evidence.
- Fake-verification warnings cover combinations of verification language, clipboard commands, Run/Terminal prompts, downloads and browser-repair lures. These are heuristics; legitimate documentation can resemble a lure.
- Existing interactive view, view-only mode, clipboard isolation, local paste guard, screenshots, four in-memory reports and exports remain available.
- The hosted member integration adds a duration selector and inspector administration. Owners, site admins and delegated inspector admins can edit finite shared budgets. Admins can give members access, a maximum duration and daily/monthly start allowances; only the owner delegates inspector administration. These controls do not grant general site administration.

## Finite session controls

At the hosted site, open **Member workspace → CAPTCHA Inspector → Inspector administration**. The parent login/admin application is separate from this standalone repository.

Defaults remain 60 seconds per session, five starts per UTC day, 100 per UTC month, two public starts per network per day and one shared admission lease. New time budgets reserve **300 seconds/day and 6,000 seconds/month** across everyone, including admins. Authenticated members also retain their personal start limits.

The complete requested duration is reserved atomically with start counts and the shared lease before AWS starts a browser. Failed starts count; stopping early does not refund time. Reservations belong to the UTC day/month when admitted, rather than measuring actual runtime across midnight. Configuration revisions prevent a concurrent budget change from silently being ignored by admission.

Every session has a finite provider-enforced timeout. Public sessions always use 60 seconds. A member's chosen duration must fit their permission and the global maximum. Admins use the global maximum, bounded by the provider's 28,800-second maximum. Settings require maximum session ≤ daily budget ≤ monthly budget. No unlimited values, automatic live extensions or usage resets are offered. Lowering a limit does not shorten an already running session.

These are browser admission controls, **not a hard ceiling on the entire AWS bill**. API calls, logging, storage, CDN traffic and other services remain separately billable. No additional standing VM or model inference is introduced by this release. AWS AgentCore browser use remains billable.

## Feature roadmap from comparable products

| Feature | Why it helps | Suggested phase |
|---|---|---|
| Side-by-side report comparison and highlighted changes | Follow a page as its behavior changes | Next; use existing in-memory captures |
| Redirect and iframe evidence timeline | Explain where navigation and embedded content lead | Next; bounded collection, origin-only retained audit records |
| Screenshot annotations and richer report export | Make investigations easier to review | Next; local processing |
| Viewport presets and keyboard/connection diagnostics | Improve usability and troubleshooting | Next; existing browser session |
| Authenticated read-only session sharing and explicit control handoff | Let another analyst observe without accidental input | Later; additional authorization design |
| Replay recording, retention controls and admin playback | Review activity after a session ends | Later; storage/privacy/cost design first |
| OCR, downloaded-file analysis and deeper script inspection | Cover image-only lures and deferred behavior | Later; explicit limits and isolation review |
| OS process graph, network telemetry, multiple OS/browser images | Explain execution beyond the web page | Separate architecture and cost approval |

[Browserling](https://www.browserling.com/browser-sandbox) demonstrates interactive remote browser testing. [Kasm session sharing](https://docs.kasm.com/docs/develop/how-to/workspaces-sessions/sessions/session-sharing) provides a useful model for viewer/control permissions. [ANY.RUN features](https://any.run/features/) and its [in-browser inspection](https://any.run/cybersecurity-blog/in-browser-data-inspection/) illustrate richer investigation workflows. These products have different architectures; their containment capabilities are not automatically inherited by this tool.

## Detection sources and limits

Official integration references: [Google invisible reCAPTCHA](https://developers.google.com/recaptcha/docs/invisible), [hCaptcha invisible/passive](https://docs.hcaptcha.com/invisible), [Turnstile](https://developers.cloudflare.com/turnstile/), [Cloudflare challenges](https://developers.cloudflare.com/cloudflare-challenges/concepts/how-challenges-work/), [Arkose](https://developer.arkoselabs.com/docs/standard-setup), [GeeTest v4](https://docs.geetest.com/gt4/quick_integration_guide), [Friendly Captcha v2](https://developer.friendlycaptcha.com/docs/v2/sdk/configuration), [ALTCHA v2](https://altcha.org/docs/v2/widget-integration/), and [AWS WAF JavaScript](https://docs.aws.amazon.com/waf/latest/developerguide/waf-javascript-api.html).

[Microsoft's CrashFix research](https://www.microsoft.com/en-us/security/blog/2026/02/05/clickfix-variant-crashfix-deploying-python-rat-trojan/) informed the browser-repair lure coverage. Detection is not a complete implementation of every behavior in that report.

Custom/self-hosted integrations, unseen providers, dynamically inserted widgets, closed shadow roots, iframe body content, image/canvas-only instructions and deferred external scripts can be missed. Known provider URLs and DOM markers can also be imitated. No OCR or full external script execution analysis is performed. URL checks and browser settings are **not a network firewall**; strong interactive-browser network isolation remains unresolved.

AWS references: [finite browser timeout](https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_StartBrowserSession.html) and [DynamoDB atomic transactions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html). Fixture tests exercise detection, negative/lookalike cases, authorization and quotas without starting paid browser sessions. DeepSeek supplied a bounded source review and provider-detector draft; its suggestions were independently reviewed and tested.
