'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ExplainableDetector } = require('../lib/detector.cjs');

function generateBenignEvents(count = 1000) {
  const events = [];
  const baseTime = new Date('2026-01-15T08:00:00Z').getTime();

  const users = ['user-alice', 'user-bob', 'user-charlie', 'user-david', 'user-elena'];
  const services = ['portal', 'catalog', 'identity', 'reports', 'admin-console'];

  for (let i = 0; i < count; i++) {
    const eventTimeMs = baseTime + i * 2000;
    const recvTimeMs = eventTimeMs + 50 + Math.floor(Math.random() * 50);
    const user = users[i % users.length];
    const sess = `sess-benign-${user}-${Math.floor(i / 20)}`;
    const flow = `flow-benign-${Math.floor(i / 10)}`;

    const actionType = i % 5;
    let event;

    if (actionType === 0) {
      // Normal sign-in
      event = {
        event_id: `benign-evt-${String(i).padStart(4, '0')}`,
        event_time_utc: new Date(eventTimeMs).toISOString(),
        received_time_utc: new Date(recvTimeMs).toISOString(),
        source_clock_offset_ms: 0,
        actor: user,
        source_service: 'portal',
        target_service: 'identity',
        action: 'sign_in',
        role_before: 'viewer',
        role_after: 'viewer',
        outcome: 'success',
        approval_id: '',
        session_id: sess,
        correlation_id: flow
      };
    } else if (actionType === 1 || actionType === 2) {
      // Normal catalog read
      event = {
        event_id: `benign-evt-${String(i).padStart(4, '0')}`,
        event_time_utc: new Date(eventTimeMs).toISOString(),
        received_time_utc: new Date(recvTimeMs).toISOString(),
        source_clock_offset_ms: 0,
        actor: user,
        source_service: 'portal',
        target_service: 'catalog',
        action: 'read',
        role_before: 'viewer',
        role_after: 'viewer',
        outcome: 'allow',
        approval_id: '',
        session_id: sess,
        correlation_id: flow
      };
    } else if (actionType === 3) {
      // Normal worker catalog read
      event = {
        event_id: `benign-evt-${String(i).padStart(4, '0')}`,
        event_time_utc: new Date(eventTimeMs).toISOString(),
        received_time_utc: new Date(recvTimeMs).toISOString(),
        source_clock_offset_ms: 0,
        actor: 'svc-report-worker',
        source_service: 'reports',
        target_service: 'catalog',
        action: 'read',
        role_before: 'service-reader',
        role_after: 'service-reader',
        outcome: 'allow',
        approval_id: '',
        session_id: 'sess-worker',
        correlation_id: flow
      };
    } else {
      // Occasional isolated read rejection (normal boundary authorization check)
      event = {
        event_id: `benign-evt-${String(i).padStart(4, '0')}`,
        event_time_utc: new Date(eventTimeMs).toISOString(),
        received_time_utc: new Date(recvTimeMs).toISOString(),
        source_clock_offset_ms: 0,
        actor: user,
        source_service: 'portal',
        target_service: 'billing',
        action: 'read',
        role_before: 'viewer',
        role_after: 'viewer',
        outcome: 'deny',
        approval_id: '',
        session_id: sess,
        correlation_id: flow
      };
    }

    events.push(event);
  }

  return events;
}

function main() {
  const N = 1000;
  console.log(`Generating ${N} synthetic routine / benign events...`);
  const benignEvents = generateBenignEvents(N);

  const approvalsData = {
    synthetic: true,
    changes: []
  };

  const detector = new ExplainableDetector(approvalsData);
  const results = detector.detect(benignEvents);

  const highSeverityAlerts = results.alerts.filter(a => a.severity === 'HIGH');
  const falseAlertRatePer1000 = highSeverityAlerts.length;

  console.log('================================================================');
  console.log(`BENIGN WORKLOAD EVALUATION (${N} SYNTHETIC ROUTINE EVENTS)`);
  console.log('================================================================');
  console.log(`Total Routine Events Evaluated:  ${N}`);
  console.log(`Security Alerts Triggered:       ${results.alerts.length}`);
  console.log(`High-Severity False Alerts:      ${highSeverityAlerts.length}`);
  console.log(`False Alert Rate per 1,000:      ${falseAlertRatePer1000} per 1,000 benign events`);
  console.log('================================================================\n');

  const report = {
    synthetic_events_evaluated: N,
    alerts_triggered: results.alerts.length,
    false_alert_rate_per_1000: falseAlertRatePer1000,
    status: 'measured'
  };

  const resultsDir = path.join(__dirname, '..', 'docs', 'results');
  if (!fs.existsSync(resultsDir)) {
    fs.mkdirSync(resultsDir, { recursive: true });
  }

  fs.writeFileSync(path.join(resultsDir, 'benign_evaluation_results.json'), JSON.stringify(report, null, 2), 'utf8');
}

if (require.main === module) {
  main();
}

module.exports = { generateBenignEvents };
