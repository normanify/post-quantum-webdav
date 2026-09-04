# Obsidian PQC WebDAV Sync - Implementation Plan

## Overview

An Obsidian plugin that encrypts all local vault data using post-quantum cryptography (PQC) and syncs to NextCloud WebDAV. Supports multi-device sync with chunked transfer and proper deletion handling.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Obsidian Vault                         │
├─────────────────────────────────────────────────────────────┤
│  Plugin Layer                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Crypto    │  │    Sync     │  │   Chunk Manager     │ │
│  │   Engine    │  │   Engine    │  │   (Split/Merge)     │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                    │            │
│         ▼                ▼                    ▼            │
│  ┌─────────────────────────────────────────────────────┐  │
│  │              WebDAV Client Layer                     │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   NextCloud WebDAV Server                    │
│  /encrypted-vault/                                          │
│  ├── metadata.json          (块索引、版本)                    │
│  ├── chunks/                                                │
│  │   ├── {chunk-hash-1}.bin.enc                              │
│  │   ├── {chunk-hash-2}.bin.enc                              │
│  │   └── ...                                                 │
│  └── versions/           (可选: 历史版本)                     │
└─────────────────────────────────────────────────────────────┘
```

## 1. Cryptographic Design

### 1.1 Algorithm Selection

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Key Encapsulation | ML-KEM-768 (Kyber) | For key exchange between devices |
| Digital Signature | ML-DSA-65 (Dilithium) | For integrity verification |
| Symmetric Encryption | AES-256-GCM | For actual data encryption |
| Key Derivation | HKDF-SHA256 | For deriving encryption keys |
| Hashing | SHA-256 | For chunk fingerprinting |

### 1.2 Key Management

```
Master Key (auto-generated, stored locally)
    │
    ├── ML-KEM Key Pair (for device key exchange)
    │   ├── Public Key (shared with other devices via WebDAV)
    │   └── Private Key (never leaves device)
    │
    ├── ML-DSA Key Pair (for signing)
    │   ├── Public Key
    │   └── Private Key
    │
    └── Derived Keys (for each chunk)
        └── HKDF(master_key, chunk_hash) → AES-256-GCM key
```

### 1.3 Multi-Device Key Exchange

```
Device A generates ML-KEM key pair
    │
    ▼
Upload public key to WebDAV: /public_keys/device-A.pub
    │
    ▼
Device B reads Device A's public key
    │
    ▼
Device B encapsulates shared secret with Device A's public key
    │
    ▼
Upload encapsulated key to WebDAV: /key_exchange/device-B-to-A.bin
    │
    ▼
Device A decapsulates → both have same shared secret
    │
    ▼
Use shared secret + HKDF to derive symmetric keys for sync
```

### 1.4 Encryption Flow

```
Plain File → Split into 256KB chunks
    │
    ▼
For each chunk:
  1. Compute hash: SHA-256(chunk_data)
  2. Derive key: AES_key = HKDF(master_key, chunk_hash)
  3. Encrypt: AES-256-GCM(key, chunk_data) → ciphertext + tag
  4. Sign: ML-DSA-sign(private_key, ciphertext) → signature
  5. Store: chunk_hash → {ciphertext, tag, signature}
```

## 2. Data Model

### 2.1 Chunk Metadata (metadata.json)

```json
{
  "version": 1,
  "vault_id": "unique-vault-identifier",
  "created_at": "2025-01-15T10:00:00Z",
  "updated_at": "2025-01-15T12:30:00Z",
  "chunk_size": 262144,
  "chunks": {
    "abc123...": {
      "path": "path/to/original/file.md",
      "hash": "sha256-of-plain-data",
      "size": 123456,
      "encrypted_size": 123600,
      "offset": 0,
      "created_at": "2025-01-15T10:00:00Z",
      "updated_at": "2025-01-15T12:30:00Z",
      "signature": "base64-encoded-signature",
      "status": "active"
    }
  },
  "file_index": {
    "path/to/file.md": ["chunk-hash-1", "chunk-hash-2"],
    "path/to/another.md": ["chunk-hash-3"]
  },
  "deleted": {
    "path/to/deleted.md": {
      "deleted_at": "2025-01-15T11:00:00Z",
      "chunks": ["chunk-hash-4"]
    }
  },
  "device_states": {
    "device-A": {
      "last_sync": "2025-01-15T12:30:00Z",
      "sequence": 42
    }
  }
}
```

### 2.2 Sync Protocol

```
Sync Cycle:
1. Download metadata.json from WebDAV
2. Compare with local metadata
3. Detect conflicts:
   - Same chunk modified on multiple devices
   - File modified on one device, deleted on another
4. Resolve conflicts:
   - Keep latest version (by timestamp)
   - Log conflict for user review
5. Upload changes:
   - New/modified chunks
   - Updated metadata.json
6. Garbage collect:
   - Remove orphaned chunks (deleted from all devices)
```

## 3. Chunked Transfer

### 3.1 Chunk Size

- Default: 256KB (262,144 bytes)
- Configurable: 64KB - 1MB
- Rationale: Balance between transfer efficiency and retry cost

### 3.2 Upload Flow

```
Large File (> chunk_size):
    │
    ▼
Split into chunks: [chunk_0, chunk_1, ..., chunk_n]
    │
    ▼
For each chunk (parallel upload):
  1. Check if chunk exists on server (by hash)
  2. If not exists:
     - Encrypt chunk
     - Upload chunk
  3. Update metadata.json
    │
    ▼
Upload updated metadata.json (atomic operation)
```

### 3.3 Download Flow

```
Sync Start:
    │
    ▼
Download metadata.json
    │
    ▼
Compare with local metadata:
  - New chunks → download
  - Modified chunks → re-download
  - Deleted chunks → remove locally
    │
    ▼
For each needed chunk (parallel download):
  1. Download encrypted chunk
  2. Verify signature
  3. Decrypt chunk
  4. Store locally
    │
    ▼
Reassemble files from chunks
```

### 3.4 Resumable Transfer

```json
// Transfer state stored locally
{
  "transfer_id": "uuid",
  "direction": "upload|download",
  "total_chunks": 10,
  "completed_chunks": [0, 1, 2, 3],
  "current_chunk": 4,
  "started_at": "2025-01-15T10:00:00Z"
}
```

## 4. Deletion Sync

### 4.1 Deletion Strategy

**Soft Delete with Garbage Collection:**

```
Device A deletes file.md:
    │
    ▼
1. Mark chunks as "deleted" in local metadata
2. Add to "deleted" section with timestamp
3. Sync metadata to WebDAV
    │
    ▼
Garbage Collection (configurable, default: 30 days):
    │
    ▼
Check all devices:
  - If ALL devices have synced the deletion
  - Then permanently remove chunks from WebDAV
```

### 4.2 Conflict: Delete vs Modify

```
Scenario:
  - Device A: deletes file.md
  - Device B: modifies file.md (same time window)

Resolution:
  1. Device B's version is KEPT (modification wins)
  2. Deletion is logged but not applied
  3. User is notified of conflict
  4. Manual resolution available in settings
```

### 4.3 Conflict Resolution Matrix

| Device A | Device B | Result |
|----------|----------|--------|
| Modify | Modify (newer) | Keep Device B |
| Modify | Modify (same time) | Keep Device with higher device_id |
| Delete | Modify | Keep modification |
| Delete | Delete | Permanent delete (after GC) |

## 5. Multi-Device Sync

### 5.1 Device Registration

```
First launch:
    │
    ▼
1. Generate device_id (UUID)
2. Generate ML-KEM key pair
3. Generate ML-DSA key pair
4. Upload public keys to WebDAV: /public_keys/{device_id}/
5. Create initial metadata.json
```

### 5.2 Sync Protocol

```
Every sync interval (configurable, default: 5 minutes):
    │
    ▼
1. Download latest metadata.json
2. Compare with local metadata:
   - Detect new/modified/deleted chunks
   - Detect conflicts
3. Resolve conflicts (see 4.3)
4. Download new/modified chunks
5. Upload new/modified chunks
6. Update local metadata
7. Upload updated metadata.json
```

### 5.3 Conflict Detection

```javascript
function detectConflicts(localMeta, remoteMeta) {
  const conflicts = [];
  
  for (const [hash, remoteChunk] of Object.entries(remoteMeta.chunks)) {
    const localChunk = localMeta.chunks[hash];
    
    if (!localChunk) {
      // New chunk on remote
      continue;
    }
    
    // Check if modified on both devices
    if (remoteChunk.updated_at > localChunk.updated_at &&
        localChunk.device_id !== remoteChunk.device_id) {
      conflicts.push({
        type: 'modify-modify',
        hash,
        local: localChunk,
        remote: remoteChunk
      });
    }
  }
  
  // Check for delete-modify conflicts
  for (const [path, deleted] of Object.entries(remoteMeta.deleted)) {
    const localFile = localMeta.file_index[path];
    if (localFile && localFile.updated_at > deleted.deleted_at) {
      conflicts.push({
        type: 'delete-modify',
        path,
        deleted,
        local_chunks: localFile
      });
    }
  }
  
  return conflicts;
}
```

## 6. Configuration

### 6.1 Settings UI

```yaml
WebDAV Settings:
  - Server URL: https://your-nextcloud.com/remote.php/dav/files/username/
  - Username: string
  - Password/Token: string (stored securely)
  - Vault Folder: /encrypted-vault (default)

Encryption Settings:
  - Auto-generate keys: checkbox (default: true)
  - Key backup: export/import keys

Sync Settings:
  - Auto-sync: checkbox (default: true)
  - Sync interval: dropdown (1min, 5min, 15min, 30min, manual)
  - Chunk size: dropdown (64KB, 128KB, 256KB, 512KB, 1MB)
  - Parallel uploads: number (default: 3)
  - Parallel downloads: number (default: 3)

Advanced Settings:
  - Conflict resolution: dropdown (latest-wins, manual)
  - Garbage collection: dropdown (7d, 30d, 90d, never)
  - Log level: dropdown (error, warn, info, debug)
```

## 7. Implementation Phases

### Phase 1: Core Infrastructure (DONE)

- [x] Project setup (TypeScript, Rollup, Obsidian plugin template)
- [x] WebDAV client wrapper
- [x] Basic crypto module (AES-256-GCM)
- [x] Chunk manager (split/merge)

### Phase 2: PQC Integration (DONE)

- [x] Integrate @noble/post-quantum (ML-DSA-65 + ML-KEM-768)
- [x] ML-KEM key encapsulation (optional; passphrase-derived secret used for MVP)
- [x] ML-DSA signing/verification
- [x] Key management system (PBKDF2-SHA512 passphrase → master secret)

### Phase 3: Sync Engine (DONE)

- [x] Metadata management (metadata.json)
- [x] Conflict detection (vector clocks + timestamps)
- [x] Deletion tracking + GC
- [x] Vault master secret (shared passphrase across devices)
- [x] Filename encryption (deterministic HKDF)
- [x] LWW conflict resolution (modify-modify, delete-modify, modify-delete, rollback)

### Phase 4: UI & Settings (DONE)

- [x] Settings tab (WebDAV, encryption, sync options)
- [x] Sync status indicator (status bar)
- [x] Manual sync trigger (ribbon + command palette)
- [x] Auto-sync on schedule + file-change watching (debounced)

### Phase 5: Testing & Polish (IN PROGRESS)

- [x] Integration tests (e2e server 10/10, two-device 12/12)
- [x] Browser-compatibility verification (webdav web build + WebCrypto primitives)
- [ ] Multi-device UI testing in Obsidian
- [ ] Error handling polish
- [ ] Documentation

## 8. Dependencies

```json
{
  "obsidian": "latest",
  "@anthropic-ai/sdk": "latest",
  "libsodium-wrappers": "^0.7.13",
  "webdav": "^5.3.0",
  "uuid": "^9.0.0"
}
```

## 9. Security Considerations

1. **Never store plaintext** on WebDAV server
2. **Key isolation**: Each device has unique key pair
3. **Signature verification**: Always verify before decrypting
4. **Secure storage**: Use Obsidian's built-in secret storage
5. **No key export by default**: Require explicit user action

## 10. Future Enhancements

- E2E encryption for shared vaults
- Selective sync (exclude specific folders)
- Compression before encryption
- Delta sync (only changed parts of files)
- Mobile performance optimization
