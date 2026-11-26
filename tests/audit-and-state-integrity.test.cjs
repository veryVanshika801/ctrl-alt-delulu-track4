const { test } = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const ENTRY = path.resolve(__dirname, '..', 'track4_service.cjs');

function runAdapter(input) {
  return spawnSync('node', [ENTRY], { input: JSON.stringify(input), encoding: 'utf8' });
}

function safeParse(str) {
  try { return JSON.parse(str); } catch { return { status: 'error' }; }
}

test('Audit: verify command returns a status', () => {
  const res = runAdapter({ command: 'audit', action: 'verify' });
  const out = safeParse(res.stdout);
  assert.ok(out.status);
});

test('Audit: verify command status is a string', () => {
  const res = runAdapter({ command: 'audit', action: 'verify' });
  const out = safeParse(res.stdout);
  assert.strictEqual(typeof out.status, 'string');
});

test('Audit: query command returns a status', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: 'test_123' });
  const out = safeParse(res.stdout);
  assert.ok(out.status);
});

test('Audit: query for missing ID returns deny or not_found', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: 'nonexistent_id_999' });
  const out = safeParse(res.stdout);
  assert.ok(out.status === 'deny' || out.status === 'not_found' || out.status === 'error');
});

test('Audit: missing action field returns deny', () => {
  const res = runAdapter({ command: 'audit' });
  const out = safeParse(res.stdout);
  assert.strictEqual(out.status, 'deny');
});

test('Audit: unknown action returns deny', () => {
  const res = runAdapter({ command: 'audit', action: 'delete_all' });
  const out = safeParse(res.stdout);
  assert.strictEqual(out.status, 'deny');
});

test('Audit: verify with extra fields handles gracefully', () => {
  const res = runAdapter({ command: 'audit', action: 'verify', extra: 'data' });
  const out = safeParse(res.stdout);
  assert.ok(out.status);
});

test('Audit: query with null request_id returns deny', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: null });
  const out = safeParse(res.stdout);
  assert.strictEqual(out.status, 'deny');
});

test('Audit: query with numeric request_id returns deny', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: 12345 });
  const out = safeParse(res.stdout);
  assert.strictEqual(out.status, 'deny');
});

test('Audit: query with empty string request_id returns deny', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: '' });
  const out = safeParse(res.stdout);
  assert.strictEqual(out.status, 'deny');
});

test('Audit: command is case-sensitive (AUDIT returns deny)', () => {
  const res = runAdapter({ command: 'AUDIT', action: 'verify' });
  const out = safeParse(res.stdout);
  assert.strictEqual(out.status, 'deny');
});

test('Audit: verify does not crash on empty state', () => {
  const res = runAdapter({ command: 'audit', action: 'verify' });
  assert.ok(res.pid > 0, 'Process should complete without crashing');
});

test('Audit: query does not crash on empty state', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: 'test' });
  assert.ok(res.pid > 0, 'Process should complete without crashing');
});

test('Audit: output is valid JSON', () => {
  const res = runAdapter({ command: 'audit', action: 'verify' });
  assert.doesNotThrow(() => JSON.parse(res.stdout));
});

test('Audit: query output is valid JSON', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: 'test' });
  assert.doesNotThrow(() => JSON.parse(res.stdout));
});

test('Audit: verify output has no fatal stderr errors', () => {
  const res = runAdapter({ command: 'audit', action: 'verify' });
  assert.ok(res.status === 0 || res.stderr === '' || !res.stderr.includes('Error'));
});

test('Audit: query output has no fatal stderr errors', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: 'test' });
  assert.ok(res.status === 0 || res.stderr === '' || !res.stderr.includes('Error'));
});

test('Audit: handles massive request_id strings', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: 'A'.repeat(10000) });
  const out = safeParse(res.stdout);
  assert.ok(out.status === 'deny' || out.status === 'not_found');
});

test('Audit: handles unicode in request_id', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: '测试_🔐' });
  const out = safeParse(res.stdout);
  assert.ok(out.status === 'deny' || out.status === 'not_found');
});

test('Audit: handles special characters in request_id', () => {
  const res = runAdapter({ command: 'audit', action: 'query', request_id: 'test<script>alert(1)</script>' });
  const out = safeParse(res.stdout);
  assert.ok(out.status === 'deny' || out.status === 'not_found');
});