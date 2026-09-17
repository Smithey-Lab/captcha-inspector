'use strict';

// Pure, evidence-only CAPTCHA/widget provider detection.
// Observations are reported as indicators only; presence never implies authenticity.
// No network, storage, execution, or dependencies. Deterministic output.

const MAX_URLS = 100;
const MAX_URL_LEN = 2048;
const MAX_EVIDENCE = 32;
const MAX_MARKERS = 100;
const MAX_MARKER_LEN = 2048;

// Whitelisted DOM marker names (a bounded collector supplies these; HTML is never parsed here).
const DOM_MARKERS = new Set([
  'grecaptcha',
  'h-captcha',
  'cf-turnstile',
  'frc-captcha',
  'altcha-widget',
  'geetest-captcha',
]);

function safeUrl(value) {
  if (typeof value !== 'string') return null;
  if (value.length === 0 || value.length > MAX_URL_LEN) return null;
  let url;
  try {
    url = new URL(value);
  } catch (_err) {
    return null;
  }
  if (url.protocol !== 'https:') return null;
  if (!url.hostname) return null;
  return url;
}

// Evidence form: origin + pathname only, no query string, no fragment.
function toEvidence(url) {
  return 'https://' + url.hostname + url.pathname;
}

// Exact host match (single, protocol already enforced https).
function hostIs(host, expected) {
  return host === expected;
}

// Correct dotted-suffix match: host === base or host ends with '.' + base.
// Prevents "notarkoselabs.com", "arkoselabs.com.evil.com", "evilarkoselabs.com".
function hostSuffix(host, base) {
  if (host === base) return true;
  return host.length > base.length + 1 && host.endsWith('.' + base);
}

function pathStartsWith(path, prefix) {
  return path === prefix || (prefix.endsWith('/') ? path.startsWith(prefix) : path.startsWith(prefix+'/'));
}

// CDN path-boundary helpers for Friendly Captcha.
const FRCIBLE_PKG = 'friendly-challenge';
const FRC_SDK_PKG = '@friendlycaptcha/sdk';
// Accept a package name only at a proper segment boundary.
function pathHasPackage(path, pkg) {
  const needle = '/' + pkg;
  let idx = 0;
  while ((idx = path.indexOf(needle, idx)) !== -1) {
    const after = path.charAt(idx + needle.length);
    if (after === '' || after === '/' || after === '@') return true;
    idx += needle.length;
  }
  return false;
}

function pushIfUnique(list, provider, source, evidence) {
  for (let i = 0; i < list.length; i += 1) {
    const item = list[i];
    if (item.provider === provider && item.source === source && item.evidence === evidence) return;
  }
  if (list.length < MAX_EVIDENCE) {
    list.push({ provider, source, evidence });
  }
}

function classifyScriptUrl(url, host, path, out) {
  // Google reCAPTCHA (v2/v3) and reCAPTCHA Enterprise.
  const isGoogle = hostIs(host, 'www.google.com') || hostIs(host, 'www.recaptcha.net');
  if (isGoogle && pathStartsWith(path, '/recaptcha/')) {
    pushIfUnique(out, 'reCAPTCHA', 'script', toEvidence(url));
    return;
  }

  // hCaptcha JS.
  if (hostIs(host, 'js.hcaptcha.com') && pathStartsWith(path, '/1/api.js')) {
    pushIfUnique(out, 'hCaptcha', 'script', toEvidence(url));
    return;
  }

  // Cloudflare Turnstile script.
  if (hostIs(host, 'challenges.cloudflare.com') && pathStartsWith(path, '/turnstile/')) {
    pushIfUnique(out, 'Cloudflare Turnstile', 'script', toEvidence(url));
    return;
  }

  // Cloudflare challenge-platform (managed/interstitial) script.
  if (hostIs(host, 'challenges.cloudflare.com') && pathStartsWith(path, '/cdn-cgi/challenge-platform/')) {
    pushIfUnique(out, 'Cloudflare Challenge', 'script', toEvidence(url));
    return;
  }

  // Arkose Labs / Funcaptcha v2 API script: /v2/<key>/api.js
  if (hostSuffix(host, 'arkoselabs.com')) {
    const m = /^\/v2\/[^/]+\/api\.js$/.test(path) || /^\/v2\/[^/]+\/api\.js\//.test(path + '/');
    if (/^\/v2\/[^/]+\/api\.js$/.test(path)) {
      pushIfUnique(out, 'Arkose Labs', 'script', toEvidence(url));
      return;
    }
    void m;
  }

  // GeeTest v4.
  if (hostIs(host, 'static.geetest.com') && pathStartsWith(path, '/v4/gt4.js')) {
    pushIfUnique(out, 'GeeTest', 'script', toEvidence(url));
    return;
  }

  // Friendly Captcha from known CDN hosts with package path boundary.
  if (hostIs(host, 'cdn.jsdelivr.net') || hostIs(host, 'unpkg.com')) {
    if (pathHasPackage(path, FRCIBLE_PKG) || pathHasPackage(path, FRC_SDK_PKG)) {
      pushIfUnique(out, 'Friendly Captcha', 'script', toEvidence(url));
      return;
    }
  }

  // AWS WAF CAPTCHA.
  if (hostSuffix(host, 'captcha.awswaf.com') && pathStartsWith(path, '/jsapi.js')) {
    pushIfUnique(out, 'AWS WAF CAPTCHA', 'script', toEvidence(url));
    return;
  }

  // AWS WAF challenge (token).
  if (hostSuffix(host, 'token.awswaf.com') && pathStartsWith(path, '/challenge.js')) {
    pushIfUnique(out, 'AWS WAF Challenge', 'script', toEvidence(url));
    return;
  }
}

function classifyFrameUrl(url, host, path, out) {
  // reCAPTCHA frames: /recaptcha/api2 and /recaptcha/enterprise.
  const isGoogle = hostIs(host, 'www.google.com') || hostIs(host, 'www.recaptcha.net');
  if (isGoogle && (pathStartsWith(path, '/recaptcha/api2') || pathStartsWith(path, '/recaptcha/enterprise'))) {
    pushIfUnique(out, 'reCAPTCHA', 'iframe', toEvidence(url));
    return;
  }

  // hCaptcha frames on any *.hcaptcha.com.
  if (hostSuffix(host, 'hcaptcha.com')) {
    pushIfUnique(out, 'hCaptcha', 'iframe', toEvidence(url));
    return;
  }

  // Cloudflare Turnstile frames.
  if (hostIs(host, 'challenges.cloudflare.com') && pathStartsWith(path, '/turnstile/')) {
    pushIfUnique(out, 'Cloudflare Turnstile', 'iframe', toEvidence(url));
    return;
  }

  // Cloudflare challenge-platform frames.
  if (hostIs(host, 'challenges.cloudflare.com') && pathStartsWith(path, '/cdn-cgi/challenge-platform/')) {
    pushIfUnique(out, 'Cloudflare Challenge', 'iframe', toEvidence(url));
    return;
  }

  // Arkose Labs frames.
  if (hostSuffix(host, 'arkoselabs.com')) {
    pushIfUnique(out, 'Arkose Labs', 'iframe', toEvidence(url));
    return;
  }

  // Funcaptcha frames (correct dot suffix only).
  if (hostSuffix(host, 'funcaptcha.com')) {
    pushIfUnique(out, 'Arkose Labs', 'iframe', toEvidence(url));
    return;
  }

  // GeeTest frames (cdn hosts under geetest.com).
  if (hostSuffix(host, 'geetest.com')) {
    pushIfUnique(out, 'GeeTest', 'iframe', toEvidence(url));
    return;
  }

  // AWS WAF CAPTCHA frames.
  if (hostSuffix(host, 'captcha.awswaf.com')) {
    pushIfUnique(out, 'AWS WAF CAPTCHA', 'iframe', toEvidence(url));
    return;
  }

  // AWS WAF challenge frames.
  if (hostSuffix(host, 'token.awswaf.com')) {
    pushIfUnique(out, 'AWS WAF Challenge', 'iframe', toEvidence(url));
    return;
  }
}

function classifyMarker(name, out) {
  if (DOM_MARKERS.has(name)) {
    const names={'grecaptcha':'reCAPTCHA','h-captcha':'hCaptcha','cf-turnstile':'Cloudflare Turnstile','frc-captcha':'Friendly Captcha','altcha-widget':'ALTCHA','geetest-captcha':'GeeTest'};
    pushIfUnique(out, names[name], 'marker', name);
  }
}

function detectProviders(snapshot) {
  const out = [];
  if (!snapshot || typeof snapshot !== 'object') return out;

  const scripts = Array.isArray(snapshot.scriptUrls) ? snapshot.scriptUrls : [];
  const frames = Array.isArray(snapshot.frameUrls) ? snapshot.frameUrls : [];
  const markers = Array.isArray(snapshot.widgetMarkers) ? snapshot.widgetMarkers : [];

  const scriptLimit = Math.min(scripts.length, MAX_URLS);
  for (let i = 0; i < scriptLimit; i += 1) {
    const url = safeUrl(scripts[i]);
    if (!url) continue;
    classifyScriptUrl(url, url.hostname, url.pathname, out);
  }

  const frameLimit = Math.min(frames.length, MAX_URLS);
  for (let i = 0; i < frameLimit; i += 1) {
    const url = safeUrl(frames[i]);
    if (!url) continue;
    classifyFrameUrl(url, url.hostname, url.pathname, out);
  }

  const markerLimit = Math.min(markers.length, MAX_MARKERS);
  for (let i = 0; i < markerLimit; i += 1) {
    const name = markers[i];
    if (typeof name !== 'string' || name.length === 0 || name.length > MAX_MARKER_LEN) continue;
    classifyMarker(name, out);
  }

  return out;
}

exports.detectProviders = detectProviders;
