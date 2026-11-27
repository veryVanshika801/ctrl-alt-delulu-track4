#!/usr/bin/env node
'use strict';

const { dispatch } = require('./team_app.cjs');

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  try {
    const req = JSON.parse(input);
    const result = dispatch(req);
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch (e) {
    process.stdout.write(JSON.stringify({ status: 'deny', decision: 'deny' }) + '\n');
  } finally {
    // CRITICAL: Exit immediately so the test runner doesn't hang waiting for stdin
    process.exit(0);
  }
});