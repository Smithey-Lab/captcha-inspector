'use strict';

const assert = require('assert');
const { detectProviders } = require('./captcha/providers.cjs');

function find(list, provider, source, evidence) {
  return list.some((x) => x.provider === provider && x.source === source && x.evidence === evidence);
}

const {test}=require('node:test');

// --- Google reCAPTCHA -------------------------------------------------------
test('detects reCAPTCHA script and frames, strips query/fragment', () => {
  const out = detectProviders({
    scriptUrls: ['https://www.google.com/recaptcha/api.js?render=abc#frag'],
    frameUrls: ['https://www.google.com/recaptcha/api2/anchor?k=1#x', 'https://www.recaptcha.net/recaptcha/enterprise/anchor'],
  });
  assert.ok(find(out, 'reCAPTCHA', 'script', 'https://www.google.com/recaptcha/api.js'));
  assert.ok(find(out, 'reCAPTCHA', 'iframe', 'https://www.google.com/recaptcha/api2/anchor'));
  assert.ok(find(out, 'reCAPTCHA', 'iframe', 'https://www.recaptcha.net/recaptcha/enterprise/anchor'));
});

// --- Lookalike domains ------------------------------------------------------
test('rejects lookalike domains (suffix confusion)', () => {
  const out = detectProviders({
    scriptUrls: [
      'https://notarkoselabs.com/v2/key/api.js',
      'https://arkoselabs.com.evil.com/v2/key/api.js',
      'https://evilarkoselabs.com/v2/key/api.js',
      'https://arkoselabs.com.evil.com/v2/k/api.js',
      'https://fakerecaptcha.com/recaptcha/api.js',
      'https://google.com.evil.com/recaptcha/api.js',
      'https://www.google.com.evil.com/recaptcha/api.js',
      'https://evilfuncaptcha.com/fc/gc/',
      'https://hcaptcha.com.evil.com/1/api.js',
      'https://notchallenges.cloudflare.com/turnstile/v0/api.js',
      'https://awswaf.com.evil.com/jsapi.js',
    ],
    frameUrls: [
      'https://notfuncaptcha.com/fc/gc/',
      'https://hcaptcha.com.evil.com/iframe',
      'https://arkoselabs.com.evil.com/iframe',
    ],
  });
  assert.deepStrictEqual(out, []);
});

// --- http rejected ----------------------------------------------------------
test('rejects http protocol', () => {
  const out = detectProviders({
    scriptUrls: ['http://www.google.com/recaptcha/api.js', 'http://static.geetest.com/v4/gt4.js'],
    frameUrls: ['http://hcaptcha.com/iframe'],
  });
  assert.deepStrictEqual(out, []);
});

// --- Wrong path -------------------------------------------------------------
test('rejects known host with wrong path', () => {
  const out = detectProviders({
    scriptUrls: [
      'https://www.google.com/notrecaptcha/api.js',
      'https://js.hcaptcha.com/2/api.js',
      'https://challenges.cloudflare.com/not-turnstile/v0/api.js',
      'https://static.geetest.com/v3/gt3.js',
      'https://cdn.jsdelivr.net/npm/notfriendlycaptcha/index.js',
    ],
    frameUrls: ['https://www.google.com/recaptcha/evil', 'https://challenges.cloudflare.com/noturnstile/v0/'],
  });
  assert.deepStrictEqual(out, []);
});

// --- hCaptcha / Turnstile / Cloudflare challenge ----------------------------
test('detects hCaptcha, Turnstile, Cloudflare challenge', () => {
  const out = detectProviders({
    scriptUrls: [
      'https://js.hcaptcha.com/1/api.js',
      'https://challenges.cloudflare.com/turnstile/v0/api.js',
      'https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page',
    ],
    frameUrls: ['https://newassets.hcaptcha.com/iframe'],
  });
  assert.ok(find(out, 'hCaptcha', 'script', 'https://js.hcaptcha.com/1/api.js'));
  assert.ok(find(out, 'hCaptcha', 'iframe', 'https://newassets.hcaptcha.com/iframe'));
  assert.ok(find(out, 'Cloudflare Turnstile', 'script', 'https://challenges.cloudflare.com/turnstile/v0/api.js'));
  assert.ok(find(out, 'Cloudflare Challenge', 'script', 'https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page'));
});

// --- Arkose / Funcaptcha ----------------------------------------------------
test('detects Arkose and Funcaptcha frames, correct dot suffix', () => {
  const out = detectProviders({
    scriptUrls: ['https://client-api.arkoselabs.com/v2/KEY123/api.js'],
    frameUrls: ['https://iframes.example.funcaptcha.com/fc/gc/', 'https://arks.example.arkoselabs.com/fc/'],
  });
  assert.ok(find(out, 'Arkose Labs', 'script', 'https://client-api.arkoselabs.com/v2/KEY123/api.js'));
  assert.ok(find(out, 'Arkose Labs', 'iframe', 'https://iframes.example.funcaptcha.com/fc/gc/'));
  assert.ok(find(out, 'Arkose Labs', 'iframe', 'https://arks.example.arkoselabs.com/fc/'));
});

// --- GeeTest ----------------------------------------------------------------
test('detects GeeTest v4 script', () => {
  const out = detectProviders({ scriptUrls: ['https://static.geetest.com/v4/gt4.js?x=1'] });
  assert.ok(find(out, 'GeeTest', 'script', 'https://static.geetest.com/v4/gt4.js'));
});

// --- Friendly Captcha CDN ---------------------------------------------------
test('detects Friendly Captcha CDN with path boundary', () => {
  const out = detectProviders({
    scriptUrls: [
      'https://cdn.jsdelivr.net/npm/@friendlycaptcha/sdk@1/index.min.js',
      'https://unpkg.com/friendly-challenge@1/index.js',
    ],
  });
  assert.ok(find(out, 'Friendly Captcha', 'script', 'https://cdn.jsdelivr.net/npm/@friendlycaptcha/sdk@1/index.min.js'));
  assert.ok(find(out, 'Friendly Captcha', 'script', 'https://unpkg.com/friendly-challenge@1/index.js'));
});

test('rejects Friendly Captcha substring without path boundary', () => {
  const out = detectProviders({
    scriptUrls: [
      'https://cdn.jsdelivr.net/npm/notfriendlycaptcha/index.js',
      'https://unpkg.com/xfriendlycaptchax/index.js',
    ],
  });
  assert.deepStrictEqual(out, []);
});

// --- AWS WAF ----------------------------------------------------------------
test('detects AWS WAF captcha and challenge', () => {
  const out = detectProviders({
    scriptUrls: [
      'https://abc123.captcha.awswaf.com/jsapi.js',
      'https://abc123.token.awswaf.com/challenge.js',
    ],
  });
  assert.ok(find(out, 'AWS WAF CAPTCHA', 'script', 'https://abc123.captcha.awswaf.com/jsapi.js'));
  assert.ok(find(out, 'AWS WAF Challenge', 'script', 'https://abc123.token.awswaf.com/challenge.js'));
});

// --- Widget markers ---------------------------------------------------------
test('detects whitelisted widget markers only', () => {
  const out = detectProviders({
    widgetMarkers: ['grecaptcha', 'cf-turnstile', 'altcha-widget', 'geetest-captcha', 'frc-captcha', 'h-captcha', 'unknown-marker', 'altcha'],
  });
  assert.ok(find(out, 'reCAPTCHA', 'marker', 'grecaptcha'));
  assert.ok(find(out, 'Cloudflare Turnstile', 'marker', 'cf-turnstile'));
  assert.ok(find(out, 'ALTCHA', 'marker', 'altcha-widget'));
  assert.ok(find(out, 'GeeTest', 'marker', 'geetest-captcha'));
  assert.ok(find(out, 'Friendly Captcha', 'marker', 'frc-captcha'));
  assert.ok(find(out, 'hCaptcha', 'marker', 'h-captcha'));
  assert.strictEqual(out.length, 6);
});

// --- Empty / malformed ------------------------------------------------------
test('returns empty array for empty or malformed input', () => {
  assert.deepStrictEqual(detectProviders({}), []);
  assert.deepStrictEqual(detectProviders(), []);
  assert.deepStrictEqual(detectProviders(null), []);
  assert.deepStrictEqual(detectProviders({ scriptUrls: 'nope', frameUrls: 5, widgetMarkers: {} }), []);
});

test('skips non-string and unparsable entries in mixed input', () => {
  const out = detectProviders({
    scriptUrls: [42, null, undefined, '', 'not a url', 'https://js.hcaptcha.com/1/api.js'],
    frameUrls: [true, {}, 'ftp://hcaptcha.com/x', 'https://www.google.com/recaptcha/api2/anchor'],
    widgetMarkers: [null, 7, 'grecaptcha'],
  });
  assert.ok(find(out, 'hCaptcha', 'script', 'https://js.hcaptcha.com/1/api.js'));
  assert.ok(find(out, 'reCAPTCHA', 'iframe', 'https://www.google.com/recaptcha/api2/anchor'));
  assert.ok(find(out, 'reCAPTCHA', 'marker', 'grecaptcha'));
  assert.strictEqual(out.length, 3);
});

test('rejects oversized url strings', () => {
  const big = 'https://www.google.com/recaptcha/api.js?x=' + 'a'.repeat(3000);
  assert.deepStrictEqual(detectProviders({ scriptUrls: [big] }), []);
});

// --- Dedup and bounds -------------------------------------------------------
test('deduplicates identical provider/source/evidence', () => {
  const out = detectProviders({
    scriptUrls: ['https://js.hcaptcha.com/1/api.js', 'https://js.hcaptcha.com/1/api.js?x=1'],
    frameUrls: ['https://newassets.hcaptcha.com/iframe', 'https://newassets.hcaptcha.com/iframe#z'],
  });
  assert.strictEqual(out.length, 2);
});

test('caps script and frame arrays at 100', () => {
  const scripts = [];
  for (let i = 0; i < 250; i += 1) scripts.push('https://www.google.com/recaptcha/api.js?v=' + i);
  const out = detectProviders({ scriptUrls: scripts });
  assert.strictEqual(out.length, 1);

  const extra = [];
  for (let i = 0; i < 100; i += 1) extra.push('https://www.google.com/recaptcha/api.js?v=' + i);
  const out2 = detectProviders({ scriptUrls: extra });
  assert.strictEqual(out2.length, 1);
});

test('caps results at 32 unique evidence entries', () => {
  const frames = [];
  for (let i = 0; i < 100; i += 1) frames.push('https://a' + i + '.hcaptcha.com/frame' + i);
  const out = detectProviders({ frameUrls: frames });
  assert.strictEqual(out.length, 32);
});

// --- Mixed comprehensive ----------------------------------------------------
test('mixed valid providers produce exact evidence strings', () => {
  const out = detectProviders({
    scriptUrls: [
      'https://www.google.com/recaptcha/enterprise.js?render=k#h',
      'https://js.hcaptcha.com/1/api.js',
      'https://challenges.cloudflare.com/turnstile/v0/api.js',
    ],
    frameUrls: [
      'https://www.recaptcha.net/recaptcha/api2/anchor?k=1',
      'https://challenges.cloudflare.com/turnstile/v0/iframe',
    ],
    widgetMarkers: ['cf-turnstile'],
  });
  assert.ok(find(out, 'reCAPTCHA', 'script', 'https://www.google.com/recaptcha/enterprise.js'));
  assert.ok(find(out, 'reCAPTCHA', 'iframe', 'https://www.recaptcha.net/recaptcha/api2/anchor'));
  assert.ok(find(out, 'Cloudflare Turnstile', 'script', 'https://challenges.cloudflare.com/turnstile/v0/api.js'));
  assert.ok(find(out, 'Cloudflare Turnstile', 'iframe', 'https://challenges.cloudflare.com/turnstile/v0/iframe'));
  assert.ok(find(out, 'Cloudflare Turnstile', 'marker', 'cf-turnstile'));
});

process.stdout.write('provider tests complete\n');
