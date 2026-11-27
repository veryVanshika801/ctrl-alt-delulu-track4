const { createAlert } = require('./alert-schema.cjs');

// ... inside your detection logic ...
const alert = createAlert({
  identity: actor,
  services: [sourceService, targetService],
  events: [actionType],
  rule: 'LATERAL_MOVEMENT',
  path: `${sourceService} -> ${targetService}`
});
alerts.push(alert);