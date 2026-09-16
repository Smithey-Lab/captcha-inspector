// Pure, in-memory capture-history logic. No DOM, no network, no storage.
// Bounded to MAX_REPORTS entries (one initial report plus up to three captures).



export const MAX_REPORTS = 4;

const clone = value => (value && typeof value === 'object' ? { ...value } : value);

const validTimestamp = value => {
  if (typeof value !== 'string' || !value) return false;
  return Number.isFinite(Date.parse(value));
};

/**
 * Create an isolated capture history.
 * entry.input: { id, capturedAt, report }
 * capturedAt should be an explicit ISO/displayable timestamp string.
 */
export function createCaptureHistory(now = () => Date.now()) {
  let entries = [];
  let selectedId = null;
  let cleared = null;
  let counter = 0;

  const findIndex = id => entries.findIndex(entry => entry.id === id);

  const resolveTimestamp = (report, capturedAt) => {
    if (validTimestamp(capturedAt)) return capturedAt;
    if (report && validTimestamp(report.capturedAt)) return report.capturedAt;
    return new Date(now()).toISOString();
  };

  const nextId = () => `report-${++counter}-${now()}`;

  const api = {
    /** Add a report; returns the new selected id or null if rejected. */
    add(report, capturedAt) {
      if (!report || typeof report !== 'object') return null;
      if (entries.length >= MAX_REPORTS) return null;
      const id = nextId();
      entries = entries.concat({ id, capturedAt: resolveTimestamp(report, capturedAt), report: clone(report) });
      selectedId = id;
      return id;
    },
    /** Replace the most recent entry (e.g. a re-capture). Retains position + id. */
    replace(report, capturedAt) {
      if (!report || typeof report !== 'object' || !entries.length) return null;
      const last = entries.length - 1;
      const next = entries.concat([]);
      next[last] = { ...next[last], capturedAt: resolveTimestamp(report, capturedAt), report: clone(report) };
      entries = next;
      selectedId = next[last].id;
      return selectedId;
    },
    /** Select an entry by id. Returns the selected entry or null. */
    select(id) {
      return findIndex(id) === -1 ? null : (selectedId = id, api.selected());
    },
    /** Remove a single entry's evidence locally. Returns true when removed. */
    remove(id) {
      const index = findIndex(id);
      if (index === -1) return false;
      const next = entries.concat([]);
      next.splice(index, 1);
      entries = next;
      if (selectedId === id) selectedId = next.length ? next[next.length - 1].id : null;
      return true;
    },
    /** Clear all evidence locally. Returns number of removed entries. */
    clear() {
      const removed = entries.length;
      entries = [];
      selectedId = null;
      cleared = new Date(now()).toISOString();
      return removed;
    },
    get clearedAt() { return cleared; },
    get size() { return entries.length; },
    get isFull() { return entries.length >= MAX_REPORTS; },
    get remaining() { return Math.max(0, MAX_REPORTS - entries.length); },
    list() { return entries.map(entry => ({ id: entry.id, capturedAt: entry.capturedAt })); },
    selectedId() { return selectedId; },
    selected() { const index = findIndex(selectedId); return index === -1 ? null : { ...entries[index], report: clone(entries[index].report) }; },
    report() { const entry = api.selected(); return entry ? entry.report : null; },
  };
  return api;
}

/** Human-readable relative age for an explicit captured timestamp. */
export function describeAge(capturedAt, at = Date.now()) {
  const then = Date.parse(capturedAt);
  if (!Number.isFinite(then)) return 'timestamp unavailable';
  const seconds = Math.max(0, Math.round((at - then) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  return `${Math.round(seconds / 3600)}h ago`;
}
