# Remote viewer diagnosis and validation

The DCV SDK strips leading slashes from a relative `baseUrl` and resolves it against the current page. Passing `/assets/dcv/` on `/tools/captcha-inspector/` therefore requested decoder workers under the tool route. The worker failed to load and the picture stopped updating, even while the remote browser accepted input. Use an absolute, same-origin asset URL for both public and member routes.

The controller now explicitly returns the automation stream to `DISABLED` for human control. Navigation and evidence capture enable automation temporarily and return control in `finally`, including after errors. A failed initial handover stops the new browser and returns no viewer credentials. The additional IAM permission is scoped to its browser resource.

The frontend observes asynchronous mouse and keyboard feature changes instead of querying once during startup. Automatic navigation waits five seconds after startup to respect the existing API throttle. Clipboard and file-transfer channels remain disabled. Bounded redacted SDK diagnostics stay in the page and console; they are not uploaded as user records.

## Validation on September 15, 2026

- Unit coverage includes handover on success/failure, failed startup cleanup, delayed feature notifications, stale connection suppression, absolute decoder URLs, and existing quota/security checks.
- The final authorized 60-second session opened a controlled page with HTTP 200. Mouse and keyboard features became ready. After the missing decoder assets were supplied and the same session reconnected, the page appeared and the previously typed `test` text was visible in its remote address bar. This confirms remote focus/keyboard delivery; it is not a full scrolling, touch, or form-control acceptance test.
- AWS reported that session `TERMINATED` with a 60-second timeout and no active sessions remained. The developer network exception was closed and original usage plus the new start restored. Shared daily/monthly caps were unchanged.

The permanent absolute asset URL removes the need for nested-route asset copies. Further live acceptance coverage should run within existing quotas; do not allocate extra sessions implicitly.
