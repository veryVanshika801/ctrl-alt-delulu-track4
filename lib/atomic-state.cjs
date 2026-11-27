// lib/atomic-state.cjs
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

/**
 * Objective 5: Sanitize user-supplied text to prevent log injection.
 * Strips \r, \n, \t, and null bytes.
 */
function sanitizeLogField(val) {
  return String(val ?? '').replace(/[\r\n\t\x00-\x1F\x7F]/g, ' ').trim();
}

/**
 * Objective 3: Atomic write with fsync. 
 * Prevents partial writes during crash/restart scenarios.
 */
function atomicWriteFileSync(filePath, data) {
  const dir = path.dirname(filePath);
  const tmpPath = path.join(dir, `.${path.basename(filePath)}.tmp.${crypto.randomBytes(8).toString('hex')}`);
  
  let fd;
  try {
    fd = fs.openSync(tmpPath, 'w', 0o600);
    fs.writeSync(fd, data);
    fs.fsyncSync(fd); // Force flush to disk
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  
  // Atomic rename ensures no partial state is ever read
  fs.renameSync(tmpPath, filePath);
}

/**
 * Append to audit log safely with sanitization.
 */
function appendAuditLog(logPath, entry) {
  // Sanitize all string fields in the entry
  const safeEntry = {};
  for (const [key, value] of Object.entries(entry)) {
    safeEntry[key] = typeof value === 'string' ? sanitizeLogField(value) : value;
  }
  
  const line = JSON.stringify(safeEntry) + '\n';
  
  let fd;
  try {
    fd = fs.openSync(logPath, 'a', 0o600);
    fs.writeSync(fd, line);
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

module.exports = { sanitizeLogField, atomicWriteFileSync, appendAuditLog };