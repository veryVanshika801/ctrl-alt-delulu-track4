const { test, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const path = require('node:path');

// We require the server directly to test it without spawning a child process
const server = require(path.resolve(__dirname, '..', 'server.cjs'));

let baseUrl;

before(() => {
  // Force server to listen on a random available port for testing
  const address = server.address();
  baseUrl = `http://localhost:${address.port}`;
});

after(() => {
  server.close();
});

async function fetchJson(urlPath) {
  return new Promise((resolve, reject) => {
    http.get(`${baseUrl}${urlPath}`, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); } 
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    }).on('error', reject);
  });
}

test('API: GET /api/v1/health returns 200 and healthy status', async () => {
  const res = await fetchJson('/api/v1/health');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.status, 'healthy');
  assert.strictEqual(res.body.pqcStatus, 'SECURE');
});

test('API: GET /api/v1/health includes state directory info', async () => {
  const res = await fetchJson('/api/v1/health');
  assert.ok(res.body.stateDir);
  assert.strictEqual(typeof res.body.kekInitialized, 'boolean');
});

test('API: GET /api/v1/audit returns 200 and array structure', async () => {
  const res = await fetchJson('/api/v1/audit');
  assert.strictEqual(res.status, 200);
  assert.ok(Array.isArray(res.body.entries));
  assert.strictEqual(typeof res.body.total, 'number');
});

test('API: GET /api/v1/devices returns 200 and device list', async () => {
  const res = await fetchJson('/api/v1/devices');
  assert.strictEqual(res.status, 200);
  assert.ok(Array.isArray(res.body.devices));
  assert.ok(res.body.devices.length > 0);
});

test('API: Device object has correct shape', async () => {
  const res = await fetchJson('/api/v1/devices');
  const device = res.body.devices[0];
  assert.ok(device.id);
  assert.ok(device.name);
  assert.ok(device.owner);
  assert.ok(device.status);
});

test('API: Unknown endpoint returns 404', async () => {
  const res = await fetchJson('/api/v1/unknown');
  assert.strictEqual(res.status, 404);
});

test('API: Root path serves HTML', async () => {
  return new Promise((resolve, reject) => {
    http.get(`${baseUrl}/`, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        assert.strictEqual(res.statusCode, 200);
        assert.ok(data.includes('<!DOCTYPE html>') || data.includes('Ctrl+Alt+Delulu'));
        resolve();
      });
    }).on('error', reject);
  });
});

test('API: Audit total matches entries length', async () => {
  const res = await fetchJson('/api/v1/audit');
  assert.strictEqual(res.body.total, res.body.entries.length);
});