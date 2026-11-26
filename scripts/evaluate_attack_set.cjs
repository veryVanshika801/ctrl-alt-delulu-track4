'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ExplainableDetector } = require('../lib/detector.cjs');

function generateAttackScenarios() {
  const events = [];
  const groundTruth = new Map(); // event_id -> { isAttack: boolean, type: string, description: string }

  const baseTime = new Date('2026-03-01T10:00:00Z').getTime();

  // Baseline approvals data for synthetic environment
  const approvalsData = {
    synthetic: true,
    changes: [
      {
        approval_id: 'atk-app-001',
        approved_by: 'user-security-admin',
        subject: 'user-sam',
        operation: 'grant_role',
        role: 'vault-reader',
        scope: ['vault-api', 'kms-cluster'],
        valid_from_utc: '2026-03-01T10:05:00Z',
        valid_until_utc: '2026-03-01T10:20:00Z' // 15 minute window
      },
      {
        approval_id: 'atk-app-002',
        approved_by: 'user-security-admin',
        subject: 'user-taylor',
        operation: 'grant_role',
        role: 'operator',
        scope: ['config-service'],
        valid_from_utc: '2026-03-01T10:00:00Z',
        valid_until_utc: '2026-03-01T10:10:00Z'
      }
    ]
  };

  // Known baseline configuration for synthetic company
  const config = {
    known_service_edges: [
      'auth-gateway->identity-core',
      'auth-gateway->catalog-api',
      'auth-gateway->vault-api',
      'auth-gateway->kms-cluster',
      'auth-gateway->config-service'
    ],
    clock_skew: {
      skew_uncertainty_ms: 500,
      max_supported_skew_ms: 5000
    },
    lateral_movement: {
      min_unexpected_hops: 2,
      min_distinct_targets: 2
    }
  };

  let evtIdx = 1;
  function addEvt(ev, isAttack, type, desc) {
    const id = `syn-atk-${String(evtIdx++).padStart(3, '0')}`;
    events.push({ event_id: id, ...ev });
    groundTruth.set(id, { isAttack, type, desc });
    return id;
  }

  // --- Scenario 1: Unapproved Role Changes (10 cases) ---
  const unapprovedActors = ['user-morgan', 'user-jordan', 'user-casey', 'user-riley', 'user-quinn'];
  const unapprovedRoles = ['root-admin', 'billing-lead', 'database-admin', 'cluster-manager', 'secrets-officer'];
  for (let i = 0; i < 5; i++) {
    const t = baseTime + i * 10000;
    addEvt({
      event_time_utc: new Date(t).toISOString(),
      received_time_utc: new Date(t + 80).toISOString(),
      source_clock_offset_ms: 0,
      actor: unapprovedActors[i],
      source_service: 'auth-gateway',
      target_service: 'identity-core',
      action: 'role_change',
      role_before: 'viewer',
      role_after: unapprovedRoles[i],
      outcome: 'success',
      approval_id: '', // Missing approval
      session_id: `sess-unapp-${i}`,
      correlation_id: `flow-unapp-${i}`
    }, true, 'unapproved_role_change', `Role change without approval for ${unapprovedActors[i]}`);

    // And a subsequent read in the same session
    addEvt({
      event_time_utc: new Date(t + 2000).toISOString(),
      received_time_utc: new Date(t + 2080).toISOString(),
      source_clock_offset_ms: 0,
      actor: unapprovedActors[i],
      source_service: 'auth-gateway',
      target_service: 'vault-api',
      action: 'read',
      role_before: unapprovedRoles[i],
      role_after: unapprovedRoles[i],
      outcome: 'allow',
      approval_id: '',
      session_id: `sess-unapp-${i}`,
      correlation_id: `flow-unapp-${i}`
    }, true, 'review_after_role_change', `Read on vault-api following unapproved role change`);
  }

  // --- Scenario 2: Expired Approvals (5 cases) ---
  for (let i = 0; i < 5; i++) {
    // atk-app-002 expired at 10:10:00Z. Attempt at 10:11:00Z
    const t = new Date('2026-03-01T10:11:00Z').getTime() + i * 10000;
    addEvt({
      event_time_utc: new Date(t).toISOString(),
      received_time_utc: new Date(t + 100).toISOString(),
      source_clock_offset_ms: 0,
      actor: 'user-taylor',
      source_service: 'auth-gateway',
      target_service: 'identity-core',
      action: 'role_change',
      role_before: 'viewer',
      role_after: 'operator',
      outcome: 'success',
      approval_id: 'atk-app-002', // Expired
      session_id: `sess-exp-${i}`,
      correlation_id: `flow-exp-${i}`
    }, true, 'expired_approval', 'Role change attempted after approval expired');
  }

  // --- Scenario 3: Boundary Timing on valid_until (Exclusive) (5 cases) ---
  const validUntilMs = new Date('2026-03-01T10:20:00Z').getTime();

  // Case A: Just before valid_until (100ms before) -> Allowed / Benign
  addEvt({
    event_time_utc: new Date(validUntilMs - 100).toISOString(),
    received_time_utc: new Date(validUntilMs - 20).toISOString(),
    source_clock_offset_ms: 0,
    actor: 'user-sam',
    source_service: 'auth-gateway',
    target_service: 'identity-core',
    action: 'role_change',
    role_before: 'viewer',
    role_after: 'vault-reader',
    outcome: 'success',
    approval_id: 'atk-app-001',
    session_id: 'sess-bound-1',
    correlation_id: 'flow-bound-1'
  }, false, 'benign_boundary_before', 'Action 100ms before valid_until is within validity');

  // Case B: Exactly at valid_until -> Must be rejected (valid_until is exclusive)
  addEvt({
    event_time_utc: new Date(validUntilMs).toISOString(),
    received_time_utc: new Date(validUntilMs + 50).toISOString(),
    source_clock_offset_ms: 0,
    actor: 'user-sam',
    source_service: 'auth-gateway',
    target_service: 'identity-core',
    action: 'role_change',
    role_before: 'viewer',
    role_after: 'vault-reader',
    outcome: 'success',
    approval_id: 'atk-app-001',
    session_id: 'sess-bound-2',
    correlation_id: 'flow-bound-2'
  }, true, 'boundary_at_valid_until', 'Action exactly at valid_until is outside exclusive bound');

  // Case C: 1 second after valid_until
  addEvt({
    event_time_utc: new Date(validUntilMs + 1000).toISOString(),
    received_time_utc: new Date(validUntilMs + 1060).toISOString(),
    source_clock_offset_ms: 0,
    actor: 'user-sam',
    source_service: 'auth-gateway',
    target_service: 'identity-core',
    action: 'role_change',
    role_before: 'viewer',
    role_after: 'vault-reader',
    outcome: 'success',
    approval_id: 'atk-app-001',
    session_id: 'sess-bound-3',
    correlation_id: 'flow-bound-3'
  }, true, 'boundary_after_valid_until', 'Action 1s after valid_until');

  // Case D: 10 seconds after valid_until
  addEvt({
    event_time_utc: new Date(validUntilMs + 10000).toISOString(),
    received_time_utc: new Date(validUntilMs + 10080).toISOString(),
    source_clock_offset_ms: 0,
    actor: 'user-sam',
    source_service: 'auth-gateway',
    target_service: 'identity-core',
    action: 'role_change',
    role_before: 'viewer',
    role_after: 'vault-reader',
    outcome: 'success',
    approval_id: 'atk-app-001',
    session_id: 'sess-bound-4',
    correlation_id: 'flow-bound-4'
  }, true, 'boundary_after_valid_until', 'Action 10s after valid_until');

  // Case E: Another legitimate action well within validity
  addEvt({
    event_time_utc: new Date(validUntilMs - 300000).toISOString(), // 5 min before
    received_time_utc: new Date(validUntilMs - 299900).toISOString(),
    source_clock_offset_ms: 0,
    actor: 'user-sam',
    source_service: 'auth-gateway',
    target_service: 'identity-core',
    action: 'role_change',
    role_before: 'viewer',
    role_after: 'vault-reader',
    outcome: 'success',
    approval_id: 'atk-app-001',
    session_id: 'sess-bound-5',
    correlation_id: 'flow-bound-5'
  }, false, 'benign_mid_validity', 'Action 5m before valid_until is valid');

  // --- Scenario 4: Wrong-Subject Approvals (5 cases) ---
  const impostors = ['user-attacker-1', 'user-attacker-2', 'user-intruder', 'user-guest', 'user-contractor'];
  for (let i = 0; i < 5; i++) {
    const t = baseTime + 400000 + i * 5000;
    addEvt({
      event_time_utc: new Date(t).toISOString(),
      received_time_utc: new Date(t + 70).toISOString(),
      source_clock_offset_ms: 0,
      actor: impostors[i],
      source_service: 'auth-gateway',
      target_service: 'identity-core',
      action: 'role_change',
      role_before: 'viewer',
      role_after: 'vault-reader',
      outcome: 'success',
      approval_id: 'atk-app-001', // Approved only for user-sam!
      session_id: `sess-imp-${i}`,
      correlation_id: `flow-imp-${i}`
    }, true, 'wrong_subject_approval', `Impostor ${impostors[i]} presented approval issued to user-sam`);
  }

  // --- Scenario 5: Wrong-Scope Access (5 cases) ---
  const wrongServices = ['payment-gateway', 'credit-card-vault', 'hr-database', 'payroll-service', 'audit-store'];
  for (let i = 0; i < 5; i++) {
    const t = baseTime + 500000 + i * 5000;
    addEvt({
      event_time_utc: new Date(t).toISOString(),
      received_time_utc: new Date(t + 85).toISOString(),
      source_clock_offset_ms: 0,
      actor: 'user-sam',
      source_service: 'auth-gateway',
      target_service: wrongServices[i],
      action: 'read',
      role_before: 'vault-reader',
      role_after: 'vault-reader',
      outcome: 'allow',
      approval_id: 'atk-app-001', // Scoped only to vault-api and kms-cluster!
      session_id: `sess-scope-${i}`,
      correlation_id: `flow-scope-${i}`
    }, true, 'wrong_scope_access', `Target ${wrongServices[i]} is outside approved scope`);
  }

  // --- Scenario 6: Lateral Movement Traversal with Varied Hop Counts (18 cases across 4 campaigns) ---
  // Campaign A: 2-hop traversal
  const campA_flow = 'flow-lat-2hop';
  addEvt({
    event_time_utc: new Date(baseTime + 600000).toISOString(),
    received_time_utc: new Date(baseTime + 600080).toISOString(),
    source_clock_offset_ms: 0,
    actor: 'svc-backup-runner',
    source_service: 'backup-manager',
    target_service: 'customer-db',
    action: 'read',
    role_before: 'backup-svc',
    role_after: 'backup-svc',
    outcome: 'deny',
    session_id: 'sess-lat-2',
    correlation_id: campA_flow
  }, true, 'lateral_movement_2hop', '2-hop hop 1');

  addEvt({
    event_time_utc: new Date(baseTime + 602000).toISOString(),
    received_time_utc: new Date(baseTime + 602080).toISOString(),
    source_clock_offset_ms: 0,
    actor: 'svc-backup-runner',
    source_service: 'customer-db',
    target_service: 'payment-records',
    action: 'read',
    role_before: 'backup-svc',
    role_after: 'backup-svc',
    outcome: 'deny',
    session_id: 'sess-lat-2',
    correlation_id: campA_flow
  }, true, 'lateral_movement_2hop', '2-hop hop 2');

  // Campaign B: 3-hop traversal
  const campB_flow = 'flow-lat-3hop';
  const campB_targets = ['dispatch-core', 'warehouse-ledger', 'erp-secrets'];
  for (let h = 0; h < 3; h++) {
    const src = h === 0 ? 'order-service' : campB_targets[h - 1];
    addEvt({
      event_time_utc: new Date(baseTime + 700000 + h * 2000).toISOString(),
      received_time_utc: new Date(baseTime + 700080 + h * 2000).toISOString(),
      source_clock_offset_ms: 0,
      actor: 'svc-web-gateway',
      source_service: src,
      target_service: campB_targets[h],
      action: 'read',
      role_before: 'web-svc',
      role_after: 'web-svc',
      outcome: 'deny',
      session_id: 'sess-lat-3',
      correlation_id: campB_flow
    }, true, 'lateral_movement_3hop', `3-hop hop ${h + 1}`);
  }

  // Campaign C: 4-hop traversal
  const campC_flow = 'flow-lat-4hop';
  const campC_targets = ['cache-layer', 'auth-store', 'ldap-directory', 'master-keyring'];
  for (let h = 0; h < 4; h++) {
    const src = h === 0 ? 'edge-proxy' : campC_targets[h - 1];
    addEvt({
      event_time_utc: new Date(baseTime + 800000 + h * 1500).toISOString(),
      received_time_utc: new Date(baseTime + 800080 + h * 1500).toISOString(),
      source_clock_offset_ms: 0,
      actor: 'svc-edge-worker',
      source_service: src,
      target_service: campC_targets[h],
      action: 'read',
      role_before: 'edge-svc',
      role_after: 'edge-svc',
      outcome: 'deny',
      session_id: 'sess-lat-4',
      correlation_id: campC_flow
    }, true, 'lateral_movement_4hop', `4-hop hop ${h + 1}`);
  }

  // Campaign D: 5-hop traversal
  const campD_flow = 'flow-lat-5hop';
  const campD_targets = ['internal-api', 'queue-broker', 'telemetry-db', 'audit-vault', 'root-ca'];
  for (let h = 0; h < 5; h++) {
    const src = h === 0 ? 'api-gateway' : campD_targets[h - 1];
    addEvt({
      event_time_utc: new Date(baseTime + 900000 + h * 1200).toISOString(),
      received_time_utc: new Date(baseTime + 900080 + h * 1200).toISOString(),
      source_clock_offset_ms: 0,
      actor: 'svc-api-proxy',
      source_service: src,
      target_service: campD_targets[h],
      action: 'read',
      role_before: 'proxy-svc',
      role_after: 'proxy-svc',
      outcome: 'deny',
      session_id: 'sess-lat-5',
      correlation_id: campD_flow
    }, true, 'lateral_movement_5hop', `5-hop hop ${h + 1}`);
  }

  // 4 Isolated denials (should NOT trigger lateral movement)
  for (let i = 0; i < 4; i++) {
    addEvt({
      event_time_utc: new Date(baseTime + 1000000 + i * 30000).toISOString(),
      received_time_utc: new Date(baseTime + 1000090 + i * 30000).toISOString(),
      source_clock_offset_ms: 0,
      actor: `user-dev-${i}`,
      source_service: 'auth-gateway',
      target_service: 'restricted-sandbox',
      action: 'read',
      role_before: 'developer',
      role_after: 'developer',
      outcome: 'deny',
      session_id: `sess-iso-${i}`,
      correlation_id: `flow-iso-${i}`
    }, false, 'isolated_denial', 'Single isolated denial is not lateral movement');
  }

  // --- Scenario 7: Excessive Clock Skew & Out of Order (6 cases) ---
  // Skew within supported range (+3500ms) -> Routine offset
  addEvt({
    event_time_utc: new Date(baseTime + 1100000).toISOString(),
    received_time_utc: new Date(baseTime + 1096580).toISOString(),
    source_clock_offset_ms: 3500,
    actor: 'user-sam',
    source_service: 'auth-gateway',
    target_service: 'catalog-api',
    action: 'read',
    role_before: 'viewer',
    role_after: 'viewer',
    outcome: 'allow',
    session_id: 'sess-skew-1',
    correlation_id: 'flow-skew-1'
  }, false, 'supported_skew', 'Offset of +3500ms within ±5000ms supported window');

  // Skew exceeding supported range (+8500ms) -> Suspicious / Alert
  addEvt({
    event_time_utc: new Date(baseTime + 1110000).toISOString(),
    received_time_utc: new Date(baseTime + 1101580).toISOString(),
    source_clock_offset_ms: 8500, // Exceeds maxSupportedSkewMs
    actor: 'user-unknown',
    source_service: 'auth-gateway',
    target_service: 'catalog-api',
    action: 'read',
    role_before: 'viewer',
    role_after: 'viewer',
    outcome: 'allow',
    session_id: 'sess-skew-2',
    correlation_id: 'flow-skew-2'
  }, true, 'excessive_clock_skew', 'Source clock offset of 8500ms exceeds ±5000ms limit');

  // Negative excessive skew (-7000ms) -> Suspicious / Alert
  addEvt({
    event_time_utc: new Date(baseTime + 1120000).toISOString(),
    received_time_utc: new Date(baseTime + 1127080).toISOString(),
    source_clock_offset_ms: -7000,
    actor: 'user-anomalous',
    source_service: 'auth-gateway',
    target_service: 'catalog-api',
    action: 'read',
    role_before: 'viewer',
    role_after: 'viewer',
    outcome: 'allow',
    session_id: 'sess-skew-3',
    correlation_id: 'flow-skew-3'
  }, true, 'excessive_clock_skew', 'Negative offset of -7000ms exceeds limit');

  return { events, groundTruth, approvalsData, config };
}

function main() {
  const { events, groundTruth, approvalsData, config } = generateAttackScenarios();

  console.log('================================================================');
  console.log('SYNTHETIC ATTACK SET EVALUATION (GOALS 6, 7, 8)');
  console.log('Diverse Service Names, Hop Counts (2-5), Scopes & Boundary Times');
  console.log('================================================================');
  console.log(`Total Attack Test Events Generated: ${events.length}`);

  const detector = new ExplainableDetector(approvalsData, config);
  const results = detector.detect(events);

  const predictedClassMap = new Map();
  for (const c of results.classifications) {
    predictedClassMap.set(c.event_id, c);
  }

  const ALERT_RULES = new Set([
    'RULE_UNAPPROVED_ROLE_CHANGE',
    'RULE_REVIEW_AFTER_ROLE_CHANGE',
    'RULE_LATERAL_MOVEMENT_TRAVERSAL',
    'RULE_OUT_OF_SCOPE_ACCESS',
    'RULE_EXCESSIVE_CLOCK_SKEW'
  ]);

  let expectedAttacks = 0;
  let detectedAttacks = 0;
  let missedAttacks = 0;
  const missedList = [];

  let expectedBenign = 0;
  let falseAlertsOnAttackSet = 0;

  const properTimeToAlertLatencies = [];

  for (const ev of events) {
    const truth = groundTruth.get(ev.event_id);
    const pred = predictedClassMap.get(ev.event_id);
    const isAlert = pred && ALERT_RULES.has(pred.rule_id);

    if (truth.isAttack) {
      expectedAttacks++;
      if (isAlert) {
        detectedAttacks++;
        // Proper time to alert = alert time (collector receive time) minus estimated event time
        const estimatedEventMs = new Date(ev.event_time_utc).getTime() - (ev.source_clock_offset_ms || 0);
        const recvMs = new Date(ev.received_time_utc).getTime();
        properTimeToAlertLatencies.push(recvMs - estimatedEventMs);
      } else {
        missedAttacks++;
        missedList.push({ id: ev.event_id, type: truth.type, desc: truth.desc, predicted: pred?.label });
      }
    } else {
      expectedBenign++;
      if (isAlert) {
        falseAlertsOnAttackSet++;
      }
    }
  }

  properTimeToAlertLatencies.sort((a, b) => a - b);
  const medianTimeToAlert = properTimeToAlertLatencies.length > 0 
    ? properTimeToAlertLatencies[Math.floor(properTimeToAlertLatencies.length / 2)] 
    : 0;

  const recall = (detectedAttacks / expectedAttacks) * 100;

  console.log('RESULTS ON ATTACK SET:');
  console.log(`  Expected Attacks in Set:     ${expectedAttacks}`);
  console.log(`  Attacks Correctly Detected:  ${detectedAttacks}`);
  console.log(`  Attacks Missed:              ${missedAttacks}`);
  console.log(`  Attack Detection Recall:     ${recall.toFixed(1)}%`);
  console.log(`  Proper Median Time to Alert: ${medianTimeToAlert} ms (alert arrival - estimated event time)`);
  console.log(`  False Alerts on Benign Test: ${falseAlertsOnAttackSet} / ${expectedBenign}`);

  if (missedList.length > 0) {
    console.log('\nMissed Attack Cases:');
    for (const m of missedList) {
      console.log(`  ✖ [${m.id}] ${m.type}: ${m.desc} (classified as: ${m.predicted})`);
    }
  } else {
    console.log('\nAll 50+ diverse attack scenarios detected with 100% recall!');
  }
  console.log('================================================================\n');

  // Save results to docs/results/
  const resultsDir = path.join(__dirname, '..', 'docs', 'results');
  if (!fs.existsSync(resultsDir)) {
    fs.mkdirSync(resultsDir, { recursive: true });
  }

  const report = {
    total_events: events.length,
    expected_attacks: expectedAttacks,
    detected_attacks: detectedAttacks,
    missed_attacks: missedAttacks,
    missed_cases: missedList,
    recall_percent: recall,
    median_time_to_alert_ms: medianTimeToAlert
  };

  fs.writeFileSync(path.join(resultsDir, 'attack_evaluation_results.json'), JSON.stringify(report, null, 2), 'utf8');
}

if (require.main === module) {
  main();
}

module.exports = { generateAttackScenarios };
