# CAPTCHA Inspector cost estimate

Updated September 17, 2026. USD, US East (N. Virginia), before taxes and without assuming free-tier credits. These are estimates for this tool, not the entire Smithey Lab AWS account.

## Unchanged default limits

The live configuration was checked: 60 seconds per session, 300 reserved seconds/day, 6,000/month, five starts/day, 100/month and one admission lease. Public visitors also have two starts per network/day. Raising session length does not raise the shared budget automatically. Admins can explicitly raise finite budgets, which increases potential spending.

## Browser compute

AWS lists [Browser pricing](https://aws.amazon.com/bedrock/agentcore/pricing/) at $0.0895/vCPU-hour and $0.00945/GB-hour. The [Browser quota documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html) lists 1 vCPU and 4 GB per session. Assuming the full allocation for the entire reserved duration:

| Usage | Browser compute estimate |
|---|---:|
| One 60-second session | $0.002122 |
| 100 minutes/month | $0.2122/month |
| Same usage for 12 months | $2.55/year |

Formula: seconds / 3600 * (0.0895 + 4 * 0.00945). Actual consumption-based charges can be lower. This corrects the previous approximately $0.18/month browser-only assumption; it is not an infrastructure price increase caused by the new detector.

## Other costs and practical allowance

At 100 sessions with six API operations each, even assuming every controller call reaches its 28-second timeout at 512 MB, [Lambda](https://aws.amazon.com/lambda/pricing/) compute plus request fees are approximately $0.140/month before credits. This intentionally generous calculation is 600 * 28 * 0.5 * $0.0000166667 plus 600 request fees at $0.20/million. It excludes rejected traffic and the shared member service.

Plan **$1-$3/month ($12-$36/year)** for the CAPTCHA tool at low visitor/request traffic, including browser compute and a small allowance for APIs, database operations, logs, artifact storage and live-view/static delivery. This is a planning range, not a metered forecast or billing ceiling. Video bandwidth, rejected traffic, existing shared monitoring/login/CDN charges, taxes and other site projects can change the total. No full-account spend audit was performed for this estimate.

The new detector uses existing captures, with at most 1.5 seconds of additional frame-read waiting per capture. At 400 captures/month, 1.5 seconds of Lambda time at 512 MB is approximately $0.005/month. This is an illustrative added-wait calculation, not a guarantee of exact measured CPU cost. Browser lifetime and caps remain unchanged. There is no new VM, recording storage, or per-inspection AI/model inference service. DeepSeek development review is separate from AWS operating costs.

Finite browser admission budgets limit browser starts and reserved duration. They do not cap all AWS request, bandwidth or storage charges and are not a hard dollar limit on the AWS account.
