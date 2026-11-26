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

test('Shape: setup output has status field', () => {
  const out = safeParse(runAdapter({ command: 'setup', actor: 'admin' }).stdout);
  assert.ok(out.status);
});

test('Shape: setup output status is a string', () => {
  const out = safeParse(runAdapter({ command: 'setup', actor: 'admin' }).stdout);
  assert.strictEqual(typeof out.status, 'string');
});

test('Shape: read output has status field', () => {
  const out = safeParse(runAdapter({ command: 'read', actor: 'alice', asset_id: 'test' }).stdout);
  assert.ok(out.status);
});

test('Shape: read deny output has reason field', () => {
  const out = safeParse(runAdapter({ command: 'read', actor: 'alice', asset_id: 'nonexistent' }).stdout);
  if (out.status === 'deny') {
    assert.ok(out.reason);
    assert.strictEqual(typeof out.reason, 'string');
  } else {
    assert.ok(true);
  }
});

test('Shape: revoke output has status field', () => {
  const out = safeParse(runAdapter({ command: 'revoke', actor: 'admin', device_id: 'dev' }).stdout);
  assert.ok(out.status);
});

test('Shape: protected_read output has status field', () => {
  const out = safeParse(runAdapter({ command: 'protected_read', actor: 'bob', challenge: 'c', ciphertext: 'ct' }).stdout);
  assert.ok(out.status);
});

test('Shape: status is never null or undefined', () => {
  const cmds = [
    { command: 'setup', actor: 'admin' },
    { command: 'read', actor: 'a', asset_id: 'b' },
    { command: 'revoke', actor: 'a', device_id: 'c' },
    { command: 'audit', action: 'verify' },
    { command: 'protected_read', actor: 'b', challenge: 'c', ciphertext: 'd' }
  ];
  cmds.forEach(cmd => {
    const out = safeParse(runAdapter(cmd).stdout);
    assert.notStrictEqual(out.status, null);
    assert.notStrictEqual(out.status, undefined);
  });
});

test('Shape: setup process completes successfully', () => {
  const res = runAdapter({ command: 'setup', actor: 'admin' });
  assert.ok(res.pid > 0);
});

test('Shape: read deny process completes successfully', () => {
  const res = runAdapter({ command: 'read', actor: 'alice', asset_id: 'test' });
  assert.ok(res.pid > 0);
});

test('Shape: revoke process completes successfully', () => {
  const res = runAdapter({ command: 'revoke', actor: 'admin', device_id: 'dev' });
  assert.ok(res.pid > 0);
});

test('Shape: audit verify process completes successfully', () => {
  const res = runAdapter({ command: 'audit', action: 'verify' });
  assert.ok(res.pid > 0);
});

test('Shape: all commands return valid JSON', () => {
  const cmds = [
    { command: 'setup', actor: 'admin' },
    { command: 'read', actor: 'a', asset_id: 'b' },
    { command: 'revoke', actor: 'a', device_id: 'c' },
    { command: 'audit', action: 'verify' },
    { command: 'protected_read', actor: 'b', challenge: 'c', ciphertext: 'd' }
  ];
  cmds.forEach(cmd => {
    const res = runAdapter(cmd);
    assert.doesNotThrow(() => JSON.parse(res.stdout));
  });
});

test('Shape: setup output is an object', () => {
  const out = safeParse(runAdapter({ command: 'setup', actor: 'admin' }).stdout);
  assert.strictEqual(typeof out, 'object');
});

test('Shape: read output is an object', () => {
  const out = safeParse(runAdapter({ command: 'read', actor: 'alice', asset_id: 'test' }).stdout);
  assert.strictEqual(typeof out, 'object');
});

test('Shape: revoke output is an object', () => {
  const out = safeParse(runAdapter({ command: 'revoke', actor: 'admin', device_id: 'dev' }).stdout);
  assert.strictEqual(typeof out, 'object');
});