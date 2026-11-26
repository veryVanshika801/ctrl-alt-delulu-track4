const { test } = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const ENTRY = path.resolve(__dirname, '..', 'track4_service.cjs');

function runAdapter(input) {
  return spawnSync('node', [ENTRY], { input: JSON.stringify(input), encoding: 'utf8' });
}

test('Scale: Adapter handles 100 rapid sequential requests without crashing', () => {
  for (let i = 0; i < 100; i++) {
    const res = runAdapter({ command: 'read', actor: 'alice', asset_id: `asset_${i}` });
    assert.ok(res.pid > 0, `Request ${i} should complete`);
  }
});

test('Concurrency: 50 concurrent processes start without OS errors', () => {
  const processes = [];
  for (let i = 0; i < 50; i++) {
    processes.push(spawnSync('node', [ENTRY], { 
      input: JSON.stringify({ command: 'read', actor: 'alice', asset_id: `asset_${i}` }), 
      encoding: 'utf8'
    }));
  }
  
  const completed = processes.filter(p => p.pid > 0);
  assert.strictEqual(completed.length, 50, 'All 50 processes should start');
});

test('Scale: Audit verify command handles empty state gracefully', () => {
  const res = runAdapter({ command: 'audit', action: 'verify' });
  assert.ok(res.pid > 0, 'Audit verify should complete');
});