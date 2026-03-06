# Renik AI 🔐

> Cryptographic key management, certificate lifecycle, and security posture service for the Trancendos mesh.
> Zero-cost compliant — all operations use Node.js native crypto, no external services.

**Port:** `3022`
**Architecture:** Trancendos Industry 6.0 / 2060 Standard

---

## Overview

Renik AI is the mesh-wide cryptographic services provider. It manages the full lifecycle of cryptographic keys and certificates, computes and verifies hashes, and provides a continuous security posture assessment with risk scoring and recommendations.

---

## Supported Algorithms

### Key Algorithms
`AES-256` · `RSA-2048` · `RSA-4096` · `ECDSA-P256` · `ECDSA-P384` · `Ed25519`

### Hash Algorithms
`sha256` · `sha512` · `md5`

---

## Key Lifecycle

```
generated → active → rotated (new key created) → revoked / expired
```

---

## Risk Levels

| Level | Condition |
|-------|-----------|
| `low` | No expired/revoked keys, all certs valid |
| `medium` | Some expired keys or expiring certs |
| `high` | Multiple expired keys or revoked certs |
| `critical` | Critical key compromise indicators |

---

## API Reference

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service health + risk level |
| GET | `/metrics` | Runtime metrics + security posture |

### Keys

| Method | Path | Description |
|--------|------|-------------|
| GET | `/keys` | List keys (filter by algorithm, purpose, status) |
| GET | `/keys/:id` | Get a specific key (no raw material) |
| POST | `/keys` | Generate a new key |
| POST | `/keys/:id/rotate` | Rotate a key |
| POST | `/keys/:id/revoke` | Revoke a key |

### Certificates

| Method | Path | Description |
|--------|------|-------------|
| GET | `/certificates` | List certificates (filter by status) |
| GET | `/certificates/:id` | Get a specific certificate |
| POST | `/certificates` | Issue a certificate |
| POST | `/certificates/:id/revoke` | Revoke a certificate |

### Hashing

| Method | Path | Description |
|--------|------|-------------|
| POST | `/hash` | Compute a hash |
| POST | `/hash/verify` | Verify a hash |

### Security Posture

| Method | Path | Description |
|--------|------|-------------|
| GET | `/posture` | Full security posture assessment |

### Audit Log

| Method | Path | Description |
|--------|------|-------------|
| GET | `/audit` | Audit log (filterable by limit) |

### Stats

| Method | Path | Description |
|--------|------|-------------|
| GET | `/stats` | Security posture summary |

---

## Usage Examples

### Generate a Key

```bash
curl -X POST http://localhost:3022/keys \
  -H "Content-Type: application/json" \
  -d '{
    "name": "api-signing-key",
    "algorithm": "ECDSA-P256",
    "purpose": "signing",
    "expiresInDays": 365,
    "owner": "cornelius-ai"
  }'
```

### Compute a Hash

```bash
curl -X POST http://localhost:3022/hash \
  -H "Content-Type: application/json" \
  -d '{
    "input": "sensitive-data",
    "algorithm": "sha256",
    "requestedBy": "norman-ai"
  }'
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3022` | HTTP server port |
| `HOST` | `0.0.0.0` | HTTP server host |
| `LOG_LEVEL` | `info` | Pino log level |
| `POSTURE_INTERVAL_MS` | `3600000` | Periodic posture assessment interval (ms) |

---

## Development

```bash
npm install
npm run dev       # tsx watch mode
npm run build     # compile TypeScript
npm start         # run compiled output
```

---

## Default System Keys

Renik AI seeds 3 system keys on startup:
- `mesh-signing` (ECDSA-P256) — mesh message signing
- `mesh-encryption` (AES-256) — mesh data encryption
- `agent-auth` (Ed25519) — agent authentication

---

*Part of the Trancendos Industry 6.0 mesh — 2060 Standard*