'use strict';

// Every alert must name the identity, the service(s) and the event.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { ExplainableDetector } = require('../lib/detector.cjs');

const SERVICE_PATH = path.join(__dirname, '..', 'track4_service.cjs');

function run(input, stateDir) {
  return spawnSync(process.execPath, [SERVICE_PATH], {
    input: JSON.stringify(input),
    env: { ...process.env, TRACK4_STATE_DIR: stateDir },
    encoding: 'utf8'
  });
}

function assertNamed(alert) {
  assert.ok(alert.identity && typeof alert.identity === 'string', `identity missing on ${alert.rule_id}`);
  assert.ok(Array.isArray(alert.services) && alert.services.length > 0, `services missing on ${alert.rule_id}`);
  assert.ok(alert.event && typeof alert.event === 'string', `event missing on ${alert.rule_id}`);
}

test('Detector alerts name identity, services and event', () => {
  const detector = new ExplainableDetector({});
  const res = detector.detect([{
    event_id: 'evt-1',
    event_time_utc: '2026-01-15T09:00:00.000Z',
    received_time_utc: '2026-01-15T09:00:00.080Z',
    source_clock_offset_ms: 0,
    actor: 'mallory',
    source_service: 'auth-gateway',
    target_service: 'identity-core',
    action: 'role_change',
    role_before: 'viewer',
    role_after: 'admin',
    outcome: 'success',
    approval_id: '',
    session_id: 's1',
    correlation_id: 'f1'
  }]);
  assert.ok(res.alerts.length >= 1, 'expected at least one alert');
  res.alerts.forEach(assertNamed);
  assert.equal(res.alerts[0].identity, 'mallory');
  assert.ok(res.alerts[0].services.includes('identity-core'));
});

test('Adapter alerts in audit.log name identity, services and event', () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-alert-'));
  const setup = run({
    op: 'setup', owners: { asset1: 'maya' }, contents: { asset1: 'payload' },
    disabled: [], key_material: 'k-' + Date.now()
  }, stateDir);
  assert.equal(setup.status, 0);
  assert.equal(run({ op: 'revoke', actor: 'maya' }, stateDir).status, 0);
  run({ op: 'read', actor: 'maya', asset: 'asset1', request_id: 'r-alert-1' }, stateDir);

  const lines = fs.readFileSync(path.join(stateDir, 'audit.log'), 'utf8').split('\n').filter(Boolean);
  const alerts = lines.map(l => JSON.parse(l))
  .filter(r => r.type === 'record' && r.actor === 'detector' && r.op === 'alert')
    .map(r => r.details);
  assert.ok(alerts.length >= 1, 'expected an alert for a read after revocation');
  alerts.forEach(assertNamed);
  assert.equal(alerts[0].identity, 'maya');
  assert.ok(alerts[0].services.includes('asset1'));
  assert.equal(alerts[0].event, 'read');
});
