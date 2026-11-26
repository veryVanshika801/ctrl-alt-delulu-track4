#!/usr/bin/env node
/**
 * bin/alerts.cjs
 *
 * Live Security Alerts Inspector for Team Ctrl+Alt+Delulu (Track 4).
 * Reads the tamper-evident audit log and displays explainable detection alerts.
 *
 * Usage:
 *   node bin/alerts.cjs [--state-dir <dir>] [--json]
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { TamperEvidentLog } = require('../lib/tamper_log.cjs');

const args = process.argv.slice(2);
let stateDir = process.env.TRACK4_STATE_DIR || os.tmpdir();
let jsonOutput = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--state-dir' && args[i + 1]) {
    stateDir = args[i + 1];
  }
  if (args[i] === '--json') {
    jsonOutput = true;
  }
}

const logPath = path.join(stateDir, 'audit.log');
if (!fs.existsSync(logPath)) {
  if (jsonOutput) {
    console.log(JSON.stringify({ alerts: [], count: 0 }));
  } else {
    console.log(`[ALERTS] No audit log found at ${logPath}`);
  }
  process.exit(0);
}

const content = fs.readFileSync(logPath, 'utf8');
const lines = content.split('\n').filter(l => l.trim().length > 0);
const alerts = [];

for (let i = 0; i < lines.length; i++) {
  try {
    const rec = JSON.parse(lines[i]);
    if (rec.type === 'record' && (rec.actor === 'detector' || rec.action === 'alert' || (rec.details && rec.details.reason === 'ACTOR_LOCKED_OUT'))) {
      alerts.push({
        line: i + 1,
        timestamp: rec.timestamp,
        hash: rec.curr_hash ? rec.curr_hash.slice(0, 12) : null,
        actor: rec.actor,
        action: rec.action,
        alert_data: rec.details
      });
    }
  } catch (_) {}
}

if (jsonOutput) {
  console.log(JSON.stringify({ alerts, count: alerts.length }, null, 2));
} else {
  console.log(`========================================================================`);
  console.log(`[CTRL+ALT+DELULU] LIVE SECURITY ALERTS REPORT (${alerts.length} ALERTS FOUND)`);
  console.log(`Log file: ${logPath}`);
  console.log(`========================================================================`);

  if (alerts.length === 0) {
    console.log('No security alerts or automated lockout actions recorded in audit log.');
  } else {
    alerts.forEach((al, idx) => {
      const dt = al.alert_data || {};
      console.log(`\n[ALERT #${idx + 1}] Rule: ${dt.rule_id || 'ALERT'} | Severity: ${dt.severity || 'HIGH'}`);
      console.log(`  Identity:  ${dt.identity || dt.actor || al.actor}`);
      console.log(`  Services:  ${Array.isArray(dt.services) ? dt.services.join(', ') : (dt.services || 'n/a')}`);
      console.log(`  Event:     ${dt.event || al.action || 'n/a'}`);
      console.log(`  Reason:    ${dt.reason || 'Security policy violation'}`);
      console.log(`  Timestamp: ${al.timestamp} | Log Hash: sha256:${al.hash}`);
    });
  }
  console.log(`\n========================================================================`);
}
