const test = require('node:test');
const assert = require('node:assert/strict');

const load = () => import('../src/captcha-history.js');

const report = (name) => ({
  requestedUrl: `https://${name}.example/`,
  url: `https://${name}.example/`,
  verdict: name,
  findings: [],
  limitations: [],
});

test('starts empty and reports capacity', async () => {
  const { createCaptureHistory, MAX_REPORTS } = await load();
  const history = createCaptureHistory();
  assert.equal(MAX_REPORTS, 4);
  assert.equal(history.size, 0);
  assert.equal(history.remaining, 4);
  assert.equal(history.isFull, false);
  assert.equal(history.report(), null);
});

test('retains one initial report plus three captures, capped at four', async () => {
  const { createCaptureHistory } = await load();
  const history = createCaptureHistory();
  for (let i = 0; i < 4; i++) assert.ok(history.add(report(`site${i}`), `2024-01-0${i + 1}T00:00:00.000Z`));
  assert.equal(history.size, 4);
  assert.equal(history.isFull, true);
  assert.equal(history.remaining, 0);
  assert.equal(history.add(report('overflow')), null, 'fifth report is rejected');
  assert.equal(history.size, 4);
});

test('newest report is selected and selectable by id', async () => {
  const { createCaptureHistory } = await load();
  const history = createCaptureHistory();
  history.add(report('first'), '2024-02-01T10:00:00.000Z');
  const second = history.add(report('second'), '2024-02-01T10:00:20.000Z');
  assert.equal(history.selectedId(), second);
  const first = history.list()[0].id;
  assert.equal(history.select(first).report.verdict, 'first');
  assert.equal(history.report().verdict, 'first');
  assert.equal(history.select('missing'), null);
});

test('exposes explicit captured timestamps', async () => {
  const { createCaptureHistory } = await load();
  const history = createCaptureHistory();
  history.add(report('timed'), '2024-03-01T12:34:56.000Z');
  assert.equal(history.list()[0].capturedAt, '2024-03-01T12:34:56.000Z');
});

test('uses value.capturedAt when the argument is not a valid timestamp', async () => {
  const { createCaptureHistory } = await load();
  const history = createCaptureHistory();
  history.add({ ...report('serverside'), capturedAt: '2024-07-04T01:02:03.000Z' }, 'not-a-timestamp');
  assert.equal(history.list()[0].capturedAt, '2024-07-04T01:02:03.000Z');
});

test('falls back to the current time when no valid timestamp exists', async () => {
  const { createCaptureHistory } = await load();
  const fixed = Date.parse('2024-08-01T00:00:00.000Z');
  const history = createCaptureHistory(() => fixed);
  history.add(report('no-stamp'));
  assert.equal(history.list()[0].capturedAt, '2024-08-01T00:00:00.000Z');
});

test('replace re-uses the newest slot without growing', async () => {
  const { createCaptureHistory } = await load();
  const history = createCaptureHistory();
  history.add(report('a'), '2024-04-01T00:00:00.000Z');
  const id = history.replace(report('a-updated'), '2024-04-01T00:00:30.000Z');
  assert.equal(history.size, 1);
  assert.equal(history.report().verdict, 'a-updated');
  assert.equal(history.list()[0].id, id);
});

test('remove clears one entry locally and reselects', async () => {
  const { createCaptureHistory } = await load();
  const history = createCaptureHistory();
  history.add(report('keep'), '2024-05-01T00:00:00.000Z');
  const second = history.add(report('drop'), '2024-05-01T00:00:20.000Z');
  assert.equal(history.remove(second), true);
  assert.equal(history.size, 1);
  assert.equal(history.report().verdict, 'keep');
  assert.equal(history.remove(second), false);
});

test('ids stay unique across remove/add within the same clock tick', async () => {
  const { createCaptureHistory } = await load();
  const fixed = Date.parse('2024-09-01T00:00:00.000Z');
  const history = createCaptureHistory(() => fixed);
  const first = history.add(report('one'));
  history.remove(first);
  const second = history.add(report('two'));
  assert.notEqual(first, second);
  assert.equal(history.size, 1);
  assert.equal(history.list()[0].id, second);
});

test('clear removes all evidence and records a timestamp', async () => {
  const { createCaptureHistory } = await load();
  const history = createCaptureHistory();
  history.add(report('one'));
  history.add(report('two'));
  assert.equal(history.clear(), 2);
  assert.equal(history.size, 0);
  assert.equal(history.report(), null);
  assert.ok(history.clearedAt);
});

test('rejects non-object reports', async () => {
  const { createCaptureHistory } = await load();
  const history = createCaptureHistory();
  assert.equal(history.add(null), null);
  assert.equal(history.add('nope'), null);
  assert.equal(history.size, 0);
});

test('describeAge renders relative ages and handles invalid input', async () => {
  const { describeAge } = await load();
  const at = Date.parse('2024-06-01T00:10:00.000Z');
  assert.equal(describeAge('2024-06-01T00:09:30.000Z', at), '30s ago');
  assert.equal(describeAge('2024-06-01T00:00:00.000Z', at), '10m ago');
  assert.equal(describeAge('2024-05-31T22:10:00.000Z', at), '2h ago');
  assert.equal(describeAge('not-a-date', at), 'timestamp unavailable');
});
