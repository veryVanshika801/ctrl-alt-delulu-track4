# File-Based Database Schema

Instead of a traditional SQL database, this adapter uses a secure, atomic file-based persistence layer to minimize attack surface and eliminate database connection overhead.

## Directory Structure (`$TRACK4_STATE_DIR`)

| File | Permissions | Description |
| :--- | :--- | :--- |
| `kek.bin` | `0600` | 32-byte Key Encryption Key (AES-256-GCM). |
| `store.enc` | `0600` | Envelope-encrypted asset store. |
| `audit.log` | `0600` | Append-only, SHA-256 hash-chained JSON Lines audit log. |
| `audit_index.json`| `0600` | O(1) indexed lookup table for audit requests. |
| `state.lock` | `0644` | `O_EXCL` atomic lockfile for concurrency safety. |
| `ticket_key.bin` | `0600` | Ephemeral key for PQC messaging resumption tickets. |