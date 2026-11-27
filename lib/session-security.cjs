// lib/session-security.cjs
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { atomicWriteFileSync } = require('./atomic-state.cjs');

const REPLAY_WINDOW_SIZE = 1024;

class ReplayProtector {
  constructor(stateDir) {
    this.filePath = path.join(stateDir, 'replay_window.json');
    this.window = new Set();
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const data = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
        this.window = new Set(data.recent_hashes || []);
      }
    } catch (e) {
      this.window = new Set();
    }
  }

  /**
   * Objective 9: Reject duplicate messages. 
   * Key is (sender, message_id, sequence).
   */
  isReplay(sender, messageId, sequence) {
    const key = `${sender}:${messageId}:${sequence}`;
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    
    if (this.window.has(hash)) {
      return true; // It's a replay
    }
    
    this.window.add(hash);
    if (this.window.size > REPLAY_WINDOW_SIZE) {
      // Remove oldest (simple FIFO for Set)
      const firstKey = this.window.keys().next().value;
      this.window.delete(firstKey);
    }
    
    this.save();
    return false;
  }

  save() {
    atomicWriteFileSync(this.filePath, JSON.stringify({ recent_hashes: Array.from(this.window) }));
  }
}

/**
 * Objective 12: Session Resumption Binding.
 * Prevents a different identity from inheriting a session ID.
 */
function validateSessionTicket(ticketIdentityBuffer, currentIdentityString) {
  const currentBuffer = Buffer.from(currentIdentityString, 'utf8');
  
  // Must be same length for timingSafeEqual
  if (ticketIdentityBuffer.length !== currentBuffer.length) {
    throw new Error('SESSION_IDENTITY_MISMATCH');
  }
  
  if (!crypto.timingSafeEqual(ticketIdentityBuffer, currentBuffer)) {
    throw new Error('SESSION_IDENTITY_MISMATCH');
  }
  
  return true;
}

module.exports = { ReplayProtector, validateSessionTicket };