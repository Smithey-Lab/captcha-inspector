# Live interaction investigation

Status: unresolved. A live video connection must not be treated as proof of working input.

Two bounded developer sessions on September 15, 2026 reproduced missing mouse/keyboard interaction. One opened a controlled input page successfully; another encountered a failed navigation request while the viewer connected. Initial DCV feature queries reported unconfirmed mouse and keyboard capabilities. Reconnecting near expiry also produced SDK cleanup exceptions. These observations do not yet establish a single root cause.

A browser-only compatibility check confirmed that gamepad enumeration, DOMMatrix, keyboard API presence and secure-context detection were available in the tested embedded browser. No remote session was needed for that check.

The client now retains up to eight redacted input/channel diagnostic messages in the display element's `data-diagnostics` attribute and browser console. This includes input-channel construction failures that earlier logging discarded. Diagnostics remain local to the page; they are not uploaded as user records.

Both developer sessions terminated. The temporary network allowance was closed and original usage restored; shared daily/monthly limits and the AWS 60-second timeout were unchanged. Further live testing requires remaining quota or an explicitly approved developer allowance. Do not label the interaction issue fixed until pointer, keyboard and scrolling behavior have been demonstrated through the live viewer.
