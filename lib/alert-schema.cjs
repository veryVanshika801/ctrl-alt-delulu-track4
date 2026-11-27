// lib/alert-schema.cjs
'use strict';

/**
 * Enforces the exact schema required by Track 4 Objective 7.
 * Every alert MUST name: identity, services, events, rule, path.
 */
function createAlert({ identity, services, events, rule, path, severity = 'HIGH' }) {
  if (!identity || typeof identity !== 'string') {
    throw new Error('ALERT_SCHEMA_INVALID: identity is required and must be a string');
  }
  if (!rule || typeof rule !== 'string') {
    throw new Error('ALERT_SCHEMA_INVALID: rule is required');
  }
  if (!path || typeof path !== 'string') {
    throw new Error('ALERT_SCHEMA_INVALID: path is required');
  }

  // Normalize services and events to arrays of strings
  const normServices = Array.isArray(services) ? services.map(String) : [String(services || 'unknown')];
  const normEvents = Array.isArray(events) ? events.map(String) : [String(events || 'unknown')];

  return {
    identity,
    services: normServices,
    events: normEvents,
    rule,
    path,
    severity,
    timestamp: new Date().toISOString(),
    detected_at_utc: Date.now()
  };
}

module.exports = { createAlert };