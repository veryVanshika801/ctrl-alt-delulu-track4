'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const STATE_DIR = process.env.TRACK4_STATE_DIR || path.join(__dirname, '..', '.track4');
const REPLAY_FILE = path.join(STATE_DIR, 'replay_window.json');
const REPLAY_SIZE = 1024;

// ==================== PERSISTENT REPLAY WINDOW ====================
class ReplayProtector {
  constructor() {
    this.window = new Set();
    this.load();
  }
  load() {
    try {
      if (fs.existsSync(REPLAY_FILE)) {
        const raw = JSON.parse(fs.readFileSync(REPLAY_FILE, 'utf8'));
        this.window = new Set(raw.recent || []);
      }
    } catch (e) { this.window = new Set(); }
  }
  save() {
    try {
      const tmp = REPLAY_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify({ recent: Array.from(this.window) }));
      fs.renameSync(tmp, REPLAY_FILE);
    } catch (e) {}
  }
  isReplay(sender, messageId, sequence) {
    const key = `${sender}:${messageId}:${sequence}`;
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    if (this.window.has(hash)) return true;
    this.window.add(hash);
    if (this.window.size > REPLAY_SIZE) {
      const first = this.window.keys().next().value;
      this.window.delete(first);
    }
    this.save();
    return false;
  }
}

// ==================== SESSION TICKET BINDING ====================
function validateSessionTicket(ticketIdentity, currentIdentity) {
  const a = Buffer.from(String(ticketIdentity), 'utf8');
  const b = Buffer.from(String(currentIdentity), 'utf8');
  if (a.length !== b.length) throw new Error('SESSION_IDENTITY_MISMATCH');
  if (!crypto.timingSafeEqual(a, b)) throw new Error('SESSION_IDENTITY_MISMATCH');
  return true;
}

// ==================== FORWARD-SECRET ENCRYPTION ====================
function encryptMessage(senderIdentity, recipientPubPem, plaintext, senderPrivPem) {
  let ephemeralPriv;
  try {
    const { publicKey: ephPub, privateKey: ephPriv } = crypto.kem.generateKeyPair('ml-kem-768');
    ephemeralPriv = ephPriv;

    const recipPub = crypto.createPublicKey(recipientPubPem);
    const { ciphertext: kemCt, sharedSecret } = crypto.kem.encapsulate(recipPub);

    const sessionKey = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, Buffer.from(senderIdentity), Buffer.from('track4-fs'), 32));
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
    c.setAAD(Buffer.from(recipientIdentity || 'recipient')); // recipient binding
    let enc = c.update(plaintext, 'utf8', 'hex');
    enc += c.final('hex');
    const tag = c.getAuthTag().toString('hex');

    const sig = crypto.sign('ml-dsa-65', Buffer.from(enc), senderPrivPem);

    return {
      kemCiphertext: kemCt.toString('hex'),
      ephemeralPublicKey: ephPub.export({ format: 'pem', type: 'spki' }).toString(),
      iv: iv.toString('hex'),
      ciphertext: enc,
      authTag: tag,
      signature: sig.toString('hex'),
      senderIdentity
    };
  } finally {
    if (ephemeralPriv) ephemeralPriv = null; // zeroize
  }
}

function decryptMessage(recipientPrivPem, message, replayProtector, sessionTicket, currentIdentity) {
  if (sessionTicket) validateSessionTicket(sessionTicket.identity, currentIdentity);

  if (replayProtector.isReplay(message.senderIdentity, message.ciphertext, message.sequence || 0)) {
    throw new Error('REPLAY_DETECTED');
  }

  const recipPriv = crypto.createPrivateKey(recipientPrivPem);
  const sharedSecret = crypto.kem.decapsulate(recipPriv, Buffer.from(message.kemCiphertext, 'hex'));
  const sessionKey = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, Buffer.from(message.senderIdentity), Buffer.from('track4-fs'), 32));

  const d = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.from(message.iv, 'hex'));
  d.setAAD(Buffer.from(currentIdentity));
  d.setAuthTag(Buffer.from(message.authTag, 'hex'));
  return Buffer.concat([d.update(Buffer.from(message.ciphertext, 'hex')), d.final()]).toString('utf8');
}

module.exports = { ReplayProtector, validateSessionTicket, encryptMessage, decryptMessage };