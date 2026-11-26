'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Default clock skew and uncertainty fallback constants
const DEFAULT_SKEW_UNCERTAINTY_MS = 500; // 500 ms clock uncertainty window
const DEFAULT_MAX_SUPPORTED_SKEW_MS = 5000; // +/- 5000 ms supported skew range

function loadDefaultConfig() {
  const configPath = path.join(__dirname, '..', 'detector-config.json');
  if (fs.existsSync(configPath)) {
    try {
      return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch {}
  }
  return {
    known_service_edges: [],
    clock_skew: {
      skew_uncertainty_ms: DEFAULT_SKEW_UNCERTAINTY_MS,
      max_supported_skew_ms: DEFAULT_MAX_SUPPORTED_SKEW_MS
    },
    lateral_movement: {
      min_unexpected_hops: 2,
      min_distinct_targets: 2
    }
  };
}

class EventTimelineManager {
  constructor(skewUncertaintyMs = DEFAULT_SKEW_UNCERTAINTY_MS, maxSupportedSkewMs = DEFAULT_MAX_SUPPORTED_SKEW_MS) {
    this.skewUncertaintyMs = skewUncertaintyMs;
    this.maxSupportedSkewMs = maxSupportedSkewMs;
  }

  /**
   * Process and normalize timestamps.
   * Corrected event time = event_time_utc - source_clock_offset_ms
   */
  processEvents(rawEvents) {
    const processed = [];

    for (let i = 0; i < rawEvents.length; i++) {
      const e = rawEvents[i];
      const rawEventMs = new Date(e.event_time_utc).getTime();
      const rawRecvMs = new Date(e.received_time_utc).getTime();
      const offsetMs = parseInt(e.source_clock_offset_ms || 0, 10);

      // Estimated physical event time on collector reference clock
      const estimatedEventMs = rawEventMs - offsetMs;
      const estimatedEventTimeUtc = new Date(estimatedEventMs).toISOString();

      // Time from event occurrence to arrival/alerting at collector
      const timeToAlertMs = rawRecvMs - estimatedEventMs;
      const isExcessiveSkew = Math.abs(offsetMs) > this.maxSupportedSkewMs;

      processed.push({
        ...e,
        receipt_index: i,
        raw_event_ms: rawEventMs,
        raw_recv_ms: rawRecvMs,
        source_clock_offset_ms: offsetMs,
        estimated_event_ms: estimatedEventMs,
        estimated_event_time_utc: estimatedEventTimeUtc,
        time_to_alert_ms: timeToAlertMs,
        excessive_skew: isExcessiveSkew,
        timing_uncertain: false
      });
    }

    // Detect out-of-order receipt vs estimated event time
    for (let i = 1; i < processed.length; i++) {
      const prev = processed[i - 1];
      const curr = processed[i];
      if (curr.estimated_event_ms < prev.estimated_event_ms) {
        curr.out_of_order_receipt = true;
      }
    }

    // Flag uncertainty for events occurring within clock uncertainty window
    for (let i = 0; i < processed.length; i++) {
      for (let j = i + 1; j < processed.length; j++) {
        const diff = Math.abs(processed[i].estimated_event_ms - processed[j].estimated_event_ms);
        if (diff <= this.skewUncertaintyMs && processed[i].actor === processed[j].actor) {
          processed[i].timing_uncertain = true;
          processed[j].timing_uncertain = true;
        }
      }
    }

    return processed;
  }
}

class ApprovalEngine {
  constructor(approvalsData) {
    this.changes = new Map();     // approval_id -> grant object
    this.revocations = new Map(); // approval_id -> revocation object
    this.revokedGrants = new Map(); // subject:role -> { effective_at_ms, revocation_id, scope }

    if (approvalsData && Array.isArray(approvalsData.changes)) {
      for (const ch of approvalsData.changes) {
        if (ch.operation === 'grant_role') {
          this.changes.set(ch.approval_id, {
            ...ch,
            valid_from_ms: new Date(ch.valid_from_utc).getTime(),
            valid_until_ms: new Date(ch.valid_until_utc).getTime() // Exclusive bound
          });
        } else if (ch.operation === 'revoke_role') {
          const effectiveMs = new Date(ch.effective_at_utc).getTime();
          this.revocations.set(ch.approval_id, {
            ...ch,
            effective_at_ms: effectiveMs
          });
        }
      }

      // Map revocations to corresponding grant scopes
      for (const rev of this.revocations.values()) {
        for (const grant of this.changes.values()) {
          if (grant.subject === rev.subject && grant.role === rev.role) {
            this.revokedGrants.set(grant.approval_id, {
              revocation_id: rev.approval_id,
              effective_at_ms: rev.effective_at_ms,
              scope: grant.scope || []
            });
            this.revokedGrants.set(rev.approval_id, {
              revocation_id: rev.approval_id,
              effective_at_ms: rev.effective_at_ms,
              scope: grant.scope || []
            });
          }
        }
      }
    }
  }

  isRoleChangeApproved(event) {
    const approvalId = event.approval_id;
    if (!approvalId) return { approved: false, reason: 'Missing approval_id' };

    const approval = this.changes.get(approvalId);
    if (!approval) {
      return { approved: false, reason: `Approval '${approvalId}' not found in change-control database` };
    }

    if (approval.subject !== event.actor) {
      return { approved: false, reason: `Subject mismatch: approved for '${approval.subject}', requested by '${event.actor}'` };
    }

    if (approval.role !== event.role_after) {
      return { approved: false, reason: `Role mismatch: approved for '${approval.role}', requested '${event.role_after}'` };
    }

    const t = event.estimated_event_ms;
    if (t < approval.valid_from_ms) {
      return { approved: false, reason: `Event time ${event.estimated_event_time_utc} is before valid_from ${approval.valid_from_utc}` };
    }
    if (t >= approval.valid_until_ms) {
      return { approved: false, reason: `Event time ${event.estimated_event_time_utc} is after or at exclusive valid_until ${approval.valid_until_utc}` };
    }

    return { approved: true, approval };
  }

  isAccessScopeValid(event) {
    if (!event.approval_id) return { inScope: true }; // Not an approval-scoped request
    const approval = this.changes.get(event.approval_id);
    if (!approval || !Array.isArray(approval.scope)) return { inScope: true };

    if (!approval.scope.includes(event.target_service)) {
      return {
        inScope: false,
        reason: `Service '${event.target_service}' is outside approved scope [${approval.scope.join(', ')}] for ${event.approval_id}`
      };
    }
    return { inScope: true };
  }

  isPostRevocationDenial(event) {
    if (!event.approval_id) return false;
    const revInfo = this.revokedGrants.get(event.approval_id);
    if (revInfo) {
      if (Array.isArray(revInfo.scope) && revInfo.scope.includes(event.target_service)) {
        return true;
      }
    }
    return false;
  }
}

class ExplainableDetector {
  constructor(approvalsData, options = {}) {
    const config = { ...loadDefaultConfig(), ...options };
    const skewCfg = config.clock_skew || {};
    const latCfg = config.lateral_movement || {};

    this.skewUncertaintyMs = skewCfg.skew_uncertainty_ms || DEFAULT_SKEW_UNCERTAINTY_MS;
    this.maxSupportedSkewMs = skewCfg.max_supported_skew_ms || DEFAULT_MAX_SUPPORTED_SKEW_MS;
    this.minUnexpectedHops = latCfg.min_unexpected_hops || 2;
    this.minDistinctTargets = latCfg.min_distinct_targets || 2;

    this.knownServiceEdges = new Set(config.known_service_edges || []);

    this.timelineMgr = new EventTimelineManager(this.skewUncertaintyMs, this.maxSupportedSkewMs);
    this.approvalEngine = new ApprovalEngine(approvalsData);
  }

  detect(rawEvents) {
    const events = this.timelineMgr.processEvents(rawEvents);
    const alerts = [];
    const eventClassifications = new Map();

    const sessionState = new Map();
    const flowServiceEdges = new Map();

    // Pass 1: Timeline, Approval and Role-Change Analysis
    for (const e of events) {
      const sess = e.session_id ? (sessionState.get(e.session_id) || { actor: e.actor, unapprovedRoles: new Set(), events: [] }) : null;
      if (sess && e.session_id) {
        sess.events.push(e);
        sessionState.set(e.session_id, sess);
      }

      const flow = e.correlation_id ? (flowServiceEdges.get(e.correlation_id) || []) : null;
      if (flow && e.correlation_id) {
        flow.push(e);
        flowServiceEdges.set(e.correlation_id, flow);
      }

      // 1. Role Change Validation
      if (e.action === 'role_change') {
        const check = this.approvalEngine.isRoleChangeApproved(e);
        if (!check.approved) {
          if (sess) sess.unapprovedRoles.add(e.role_after);
          eventClassifications.set(e.event_id, {
            label: 'unexpected_role_change',
            rule_id: 'RULE_UNAPPROVED_ROLE_CHANGE',
            time_to_alert_ms: e.time_to_alert_ms,
            reason: `Role change from ${e.role_before} to ${e.role_after} without valid authorization: ${check.reason}`
          });
          alerts.push({
            alert_id: `ALT-ROLE-${e.event_id}`,
            rule_id: 'RULE_UNAPPROVED_ROLE_CHANGE',
            severity: 'HIGH',
            actor: e.actor,
            event_ids: [e.event_id],
            time_to_alert_ms: e.time_to_alert_ms,
            reason: `Actor ${e.actor} escalated role to ${e.role_after} without valid approval: ${check.reason}`
          });
          continue;
        } else {
          eventClassifications.set(e.event_id, {
            label: 'approved_change',
            rule_id: 'RULE_APPROVED_CHANGE',
            time_to_alert_ms: e.time_to_alert_ms,
            reason: `Approved subject role and time match ${e.approval_id}`
          });
          continue;
        }
      }

      // 2. Approval Administration Operations
      if (e.action === 'approve_role_change' || e.action === 'revoke_role') {
        eventClassifications.set(e.event_id, {
          label: 'approved_change',
          rule_id: 'RULE_OPERATOR_ADMIN_CHANGE',
          time_to_alert_ms: e.time_to_alert_ms,
          reason: `Operator ${e.action} under ${e.approval_id || 'system authorization'}`
        });
        continue;
      }

      // 3. Post-escalation read in session with unapproved role
      if (sess && sess.unapprovedRoles.size > 0 && e.action === 'read' && e.outcome === 'allow') {
        eventClassifications.set(e.event_id, {
          label: 'review_after_role_change',
          rule_id: 'RULE_REVIEW_AFTER_ROLE_CHANGE',
          time_to_alert_ms: e.time_to_alert_ms,
          reason: `Allowed read follows unexpected role change in same session (${e.session_id})`
        });
        alerts.push({
          alert_id: `ALT-POSTROLE-${e.event_id}`,
          rule_id: 'RULE_REVIEW_AFTER_ROLE_CHANGE',
          severity: 'HIGH',
          actor: e.actor,
          event_ids: [e.event_id],
          time_to_alert_ms: e.time_to_alert_ms,
          reason: `Actor ${e.actor} executed allowed read on ${e.target_service} following unapproved role escalation`
        });
        continue;
      }

      // 4. Approval Scope Validation
      const scopeCheck = this.approvalEngine.isAccessScopeValid(e);
      if (!scopeCheck.inScope) {
        eventClassifications.set(e.event_id, {
          label: 'unauthorized_scope_access',
          rule_id: 'RULE_OUT_OF_SCOPE_ACCESS',
          time_to_alert_ms: e.time_to_alert_ms,
          reason: scopeCheck.reason
        });
        alerts.push({
          alert_id: `ALT-SCOPE-${e.event_id}`,
          rule_id: 'RULE_OUT_OF_SCOPE_ACCESS',
          severity: 'HIGH',
          actor: e.actor,
          event_ids: [e.event_id],
          time_to_alert_ms: e.time_to_alert_ms,
          reason: scopeCheck.reason
        });
        continue;
      }

      // 5. Clock Skew Handling (Supported vs Excessive)
      if (e.excessive_skew) {
        eventClassifications.set(e.event_id, {
          label: 'excessive_clock_skew',
          rule_id: 'RULE_EXCESSIVE_CLOCK_SKEW',
          time_to_alert_ms: e.time_to_alert_ms,
          reason: `Source clock offset of ${e.source_clock_offset_ms} ms exceeds supported threshold (±${this.maxSupportedSkewMs} ms)`
        });
        alerts.push({
          alert_id: `ALT-SKEW-${e.event_id}`,
          rule_id: 'RULE_EXCESSIVE_CLOCK_SKEW',
          severity: 'MEDIUM',
          actor: e.actor,
          event_ids: [e.event_id],
          time_to_alert_ms: e.time_to_alert_ms,
          reason: `Source clock offset of ${e.source_clock_offset_ms} ms exceeds supported threshold (±${this.maxSupportedSkewMs} ms)`
        });
        continue;
      } else if (Math.abs(e.source_clock_offset_ms) >= 1000) {
        eventClassifications.set(e.event_id, {
          label: 'routine_clock_offset',
          rule_id: 'RULE_SOURCE_CLOCK_OFFSET',
          time_to_alert_ms: e.time_to_alert_ms,
          reason: `Source clock is ${e.source_clock_offset_ms} milliseconds offset from collector`
        });
        continue;
      }

      // 6. Out-of-order Receipt Detection
      if (e.out_of_order_receipt) {
        eventClassifications.set(e.event_id, {
          label: 'routine_delayed_delivery',
          rule_id: 'RULE_TIMELINE_ORDERING',
          time_to_alert_ms: e.time_to_alert_ms,
          reason: `Older event arrived out of order (received after subsequent event)`
        });
        continue;
      }

      // Defer denials to Pass 2 & 3
      if (e.outcome === 'deny') {
        continue;
      }

      // Routine allowed operation
      eventClassifications.set(e.event_id, {
        label: 'routine',
        rule_id: 'RULE_ROUTINE_ACCESS',
        time_to_alert_ms: e.time_to_alert_ms,
        reason: `Routine authorized operation: ${e.actor} on ${e.target_service}`
      });
    }

    // Pass 2: Flow and Lateral Movement Graph Analysis
    for (const [flowId, flowEvents] of flowServiceEdges.entries()) {
      const unexpectedDeniedEvents = [];
      const servicePath = [];

      for (const ev of flowEvents) {
        const edge = `${ev.source_service}->${ev.target_service}`;
        // Unexpected edge if not in known baseline edges
        if (!this.knownServiceEdges.has(edge) && ev.outcome === 'deny') {
          unexpectedDeniedEvents.push(ev);
          servicePath.push(ev.target_service);
        }
      }

      const distinctTargets = new Set(servicePath);
      // Lateral movement candidate: >= minUnexpectedHops and >= minDistinctTargets
      if (unexpectedDeniedEvents.length >= this.minUnexpectedHops && distinctTargets.size >= this.minDistinctTargets) {
        const firstSrc = unexpectedDeniedEvents[0].source_service;
        const fullGraphPath = [firstSrc, ...servicePath].join(' -> ');
        const eventIds = unexpectedDeniedEvents.map(x => x.event_id);

        for (const ev of unexpectedDeniedEvents) {
          eventClassifications.set(ev.event_id, {
            label: 'lateral_movement_candidate',
            rule_id: 'RULE_LATERAL_MOVEMENT_TRAVERSAL',
            time_to_alert_ms: ev.time_to_alert_ms,
            reason: `Unexpected service edge in lateral traversal candidate (${flowId})`
          });
        }

        const lastEv = unexpectedDeniedEvents[unexpectedDeniedEvents.length - 1];
        alerts.push({
          alert_id: `ALT-LATERAL-${flowId}`,
          rule_id: 'RULE_LATERAL_MOVEMENT_TRAVERSAL',
          severity: 'HIGH',
          actor: unexpectedDeniedEvents[0].actor,
          session_id: unexpectedDeniedEvents[0].session_id,
          correlation_id: flowId,
          services_touched: [firstSrc, ...servicePath],
          graph_path: fullGraphPath,
          event_ids: eventIds,
          time_to_alert_ms: lastEv.time_to_alert_ms,
          reason: `Actor ${unexpectedDeniedEvents[0].actor} executed lateral movement traversal across unexpected service edges: ${fullGraphPath}`
        });
      }
    }

    // Pass 3: Classify remaining unclassified denials
    for (const e of events) {
      if (!eventClassifications.has(e.event_id)) {
        if (e.outcome === 'deny') {
          if (this.approvalEngine.isPostRevocationDenial(e)) {
            eventClassifications.set(e.event_id, {
              label: 'routine_denial',
              rule_id: 'RULE_POST_REVOCATION_DENIAL',
              time_to_alert_ms: e.time_to_alert_ms,
              reason: `Target ${e.target_service} denied access after role revocation (${e.approval_id})`
            });
          } else {
            eventClassifications.set(e.event_id, {
              label: 'isolated_denial',
              rule_id: 'RULE_ISOLATED_DENIAL',
              time_to_alert_ms: e.time_to_alert_ms,
              reason: 'One denied request alone does not establish lateral movement'
            });
          }
        } else {
          eventClassifications.set(e.event_id, {
            label: 'routine',
            rule_id: 'RULE_ROUTINE_ACCESS',
            time_to_alert_ms: e.time_to_alert_ms,
            reason: 'Routine operation'
          });
        }
      }
    }

    // Every alert must name the identity, the service(s) and the event.
    const eventById = new Map(events.map(ev => [ev.event_id, ev]));
    for (const a of alerts) {
      const evs = (a.event_ids || []).map(id => eventById.get(id)).filter(Boolean);
      if (a.identity === undefined) a.identity = a.actor;
      if (a.services === undefined) {
        a.services = Array.isArray(a.services_touched)
          ? [...a.services_touched]
          : [...new Set(evs.flatMap(ev => [ev.source_service, ev.target_service]).filter(Boolean))];
      }
      if (a.event === undefined) {
        a.event = evs.map(ev => `${ev.action || 'event'}#${ev.event_id}`).join(', ') || (a.event_ids || []).join(', ');
      }
    }

    return {
      events_analyzed: events.length,
      alerts,
      classifications: Array.from(eventClassifications.entries()).map(([event_id, c]) => ({
        event_id,
        ...c
      }))
    };
  }
}

module.exports = {
  DEFAULT_SKEW_UNCERTAINTY_MS,
  DEFAULT_MAX_SUPPORTED_SKEW_MS,
  loadDefaultConfig,
  EventTimelineManager,
  ApprovalEngine,
  ExplainableDetector
};
