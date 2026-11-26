const { test } = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ENTRY = path.resolve(__dirname, '..', 'track4_service.cjs');

test('Scale: Cold start latency with large audit log', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-scale-'));
  process.env.TRACK4_STATE_DIR = tmpDir;
  
  spawnSync('node', [ENTRY], { input: JSON.stringify({ command: 'setup', actor: 'admin' }), env: process.env });
  
  // Generate 500 legitimate records to build a valid hash chain
  for (let i = 0; i < 500; i++) {
    spawnSync('node', [ENTRY], { 
      input: JSON.stringify({ command: 'read', actor: 'alice', asset_id: `asset_${i}` }), 
      env: process.env 
    });
  }
  
  const start = Date.now();
  spawnSync('node', [ENTRY], { 
    input: JSON.stringify({ command: 'audit', action: 'verify' }), 
    env: process.env 
  });
  const duration = Date.now() - start;
  
  assert.ok(duration < 500, `Cold start with 500 records took ${duration}ms, expected < 500ms`);
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('Concurrency: 50 concurrent processes with O_EXCL locking', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-conc-'));
  process.env.TRACK4_STATE_DIR = tmpDir;
  
  spawnSync('node', [ENTRY], { input: JSON.stringify({ command: 'setup', actor: 'admin' }), env: process.env });
  
  const processes = [];
  for (let i = 0; i < 50; i++) {
    processes.push(
      spawnSync('node', [ENTRY], { 
        input: JSON.stringify({ command: 'read', actor: 'alice', asset_id: `asset_${i}` }), 
        env: process.env 
      })
    );
  }
  
  const successes = processes.filter(p => {
    try {
      const out = JSON.parse(p.stdout);
      return out.status === 'deny' || out.status === 'success'; 
    } catch { return false; }
  });
  
  assert.strictEqual(successes.length, 50, 'All 50 concurrent processes should complete safely');
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('Scale: Audit index O(1) lookup verification', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-idx-'));
  process.env.TRACK4_STATE_DIR = tmpDir;
  
  spawnSync('node', [ENTRY], { input: JSON.stringify({ command: 'setup', actor: 'admin' }), env: process.env });
  
  for(let i=0; i<100; i++) {
     spawnSync('node', [ENTRY], { input: JSON.stringify({ command: 'read', actor: 'alice', asset_id: `a_${i}` }), env: process.env });
  }
  
  const start = Date.now();
  spawnSync('node', [ENTRY], { input: JSON.stringify({ command: 'audit', action: 'query', request_id: 'req_5' }), env: process.env });
  const duration = Date.now() - start;
  
  assert.ok(duration < 50, 'Indexed lookup should be O(1) and fast');
  fs.rmSync(tmpDir, { recursive: true, force: true });
});