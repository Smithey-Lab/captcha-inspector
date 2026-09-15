# Deploy your own instance

Builds and GitHub Actions do not deploy automatically. Use your own AWS account, review costs and permissions, and keep credentials out of source control.

1. Run `npm ci` and `npm run build:backend`. This creates a bundled controller in `.sandbox-build/`, artifact metadata in `infra/sandbox-artifacts.json`, and `infra/captcha-cloudformation.json`.
2. Review the generated template. Use a region supporting the required AgentCore browser features (the hosted instance uses `us-east-1`). Bootstrap a stack with an empty `CodeKey` to create its private artifact bucket.
3. Upload `backend/captcha/browser-policies.json` using the policy key in the artifact metadata. Zip the contents of `.sandbox-build/` with `index.js` at the archive root and upload that archive to your private bucket.
4. Review a stack change set supplying the archive's `CodeKey`, your HTTPS frontend `AllowedOrigins`, and `Enabled=true`. The default is disabled. Creating IAM resources requires acknowledgement of the template's IAM capabilities.
5. Set `src/captcha-config.json` to your stack's Endpoint and `enabled: true`, then run `npm run build`. Host `dist/` over HTTPS. Configure your hosting CSP to permit the backend and required AgentCore HTTPS/WebSocket streams. Do not embed AWS credentials.

The DCV viewing SDK is obtained from the installed dependency during build rather than vendored into this repository. Preserve its license notices when distributing built assets. Browser names are generated from policy content; customize naming if deploying multiple instances in one account/region.

The template includes admission quotas, short session expiry, restricted role permissions and a disabled-by-default switch. Review these controls for your environment. Retained buckets/tables require separate cleanup, and TTL is asynchronous. Monitor costs independently; application quotas are not an account-wide spending cap. Authentication/member integration and an admin audit viewer require your own trusted integration.
