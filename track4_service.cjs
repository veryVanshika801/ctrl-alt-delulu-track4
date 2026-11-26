// One JSON request per process. Team code owns all application behavior.
'use strict';
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 24 || (major === 24 && minor < 11)) {
  process.stderr.write('Node >= 24.11.1 required (ML-KEM/ML-DSA support).\n');
  process.exit(1);
}
const fs = require('node:fs');
const { dispatch } = require('./team_app.cjs');

async function main() {
  try {
    const raw = fs.readFileSync(0, 'utf8');
    if (!raw || !raw.trim()) {
      throw new Error('empty request');
    }
    const request = JSON.parse(raw);
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
      throw new Error('Request must be a JSON object');
    }
    const response = await dispatch(request);
    if (!response || typeof response !== 'object' || Array.isArray(response)) {
      throw new Error('Response must be a JSON object');
    }
    process.stdout.write(JSON.stringify(response) + '\n');
  } catch (err) {
    // Generic stderr error line; never disclose secrets or stack traces
    process.stderr.write('Request failed; inspect team application locally.\n');
    process.exit(1);
  }
}

main();
