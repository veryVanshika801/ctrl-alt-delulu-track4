'use strict';

// "Rejected" must still mean rejected after a crash or a restart.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const SERVICE_PATH = path.join(__dirname, '..', 'track4_service.cjs');

function run(input, stateDir, extraEnv = {}) {
  return spawnSync(process.execPath, [SERVICE_PATH], {
    input: JSON.stringify(input),
    env: { ...process.env, TRACK4_STATE_DIR: stateDir, ...extraEnv },
    encoding: 'utf8'
  });
}

test('Revoked actor stays rejected after restart and after a crash mid-write', () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-restart-'));
  const body = 'secret-' + Date.now();

  assert.equal(run({
    op: 'setup',
    owners: { assetA: 'maya', assetB: 'alex' },
    contents: { assetA: body, assetB: 'alex-data' },
    disabled: [],
    key_material: 'k-' + Date.now()
  }, stateDir).status, 0);

  // Allowed before revocation
  let r = JSON.parse(run({ op: 'read', actor: 'maya', asset: 'assetA', request_id: 'pre-1' }, stateDir).stdout);
  assert.equal(r.decision, 'allow');

  // Revoke (each call below is a brand-new process = a restart)
  assert.equal(run({ op: 'revoke', actor: 'maya' }, stateDir).status, 0);

  r = JSON.parse(run({ op: 'read', actor: 'maya', asset: 'assetA', request_id: 'post-1' }, stateDir).stdout);
  assert.equal(r.decision, 'deny');
  assert.equal(r.body, undefined, 'revoked actor must not receive the body');

  // A crash during a later revoke must not un-revoke anyone
  run({ op: 'revoke', actor: 'someone-else' }, stateDir, { TRACK4_FAULT_HOOK: 'mid_revoke' });

  r = JSON.parse(run({ op: 'read', actor: 'maya', asset: 'assetA', request_id: 'post-2' }, stateDir).stdout);
  assert.equal(r.decision, 'deny', 'still denied after crash + restart');

  // Peers are unaffected
  r = JSON.parse(run({ op: 'read', actor: 'alex', asset: 'assetB', request_id: 'peer-1' }, stateDir).stdout);
  assert.equal(r.decision, 'allow');
});
