/**
 * Renik AI — REST API Server
 *
 * Exposes cryptographic key management, certificate lifecycle,
 * hash computation, and security posture endpoints for the Trancendos mesh.
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import {
  CryptoEngine,
  KeyAlgorithm,
  KeyPurpose,
  KeyStatus,
  CertStatus,
  HashResult,
} from '../security/crypto-engine';
import { logger } from '../utils/logger';


// ============================================================================
// IAM MIDDLEWARE — Trancendos 2060 Standard (TRN-PROD-001)
// ============================================================================
import { createHash, createHmac } from 'crypto';

const IAM_JWT_SECRET = process.env.IAM_JWT_SECRET || process.env.JWT_SECRET || '';
const IAM_ALGORITHM = process.env.JWT_ALGORITHM || 'HS512';
const SERVICE_ID = 'renik';
const MESH_ADDRESS = process.env.MESH_ADDRESS || 'renik.agent.local';

function sha512Audit(data: string): string {
  return createHash('sha512').update(data).digest('hex');
}

function b64urlDecode(s: string): string {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64 + '='.repeat((4 - b64.length % 4) % 4), 'base64').toString('utf8');
}

interface JWTClaims {
  sub: string; email?: string; role?: string;
  active_role_level?: number; permissions?: string[];
  exp?: number; jti?: string;
}

function verifyIAMToken(token: string): JWTClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, p, sig] = parts;
    const header = JSON.parse(b64urlDecode(h));
    const alg = header.alg === 'HS512' ? 'sha512' : 'sha256';
    const expected = createHmac(alg, IAM_JWT_SECRET)
      .update(`${h}.${p}`).digest('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    if (expected !== sig) return null;
    const claims = JSON.parse(b64urlDecode(p)) as JWTClaims;
    if (claims.exp && Date.now() / 1000 > claims.exp) return null;
    return claims;
  } catch { return null; }
}

function requireIAMLevel(maxLevel: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) { res.status(401).json({ error: 'Authentication required', service: SERVICE_ID }); return; }
    const claims = verifyIAMToken(token);
    if (!claims) { res.status(401).json({ error: 'Invalid or expired token', service: SERVICE_ID }); return; }
    const level = claims.active_role_level ?? 6;
    if (level > maxLevel) {
      console.log(JSON.stringify({ level: 'audit', decision: 'DENY', service: SERVICE_ID,
        principal: claims.sub, requiredLevel: maxLevel, actualLevel: level, path: req.path,
        integrityHash: sha512Audit(`DENY:${claims.sub}:${req.path}:${Date.now()}`),
        timestamp: new Date().toISOString() }));
      res.status(403).json({ error: 'Insufficient privilege level', required: maxLevel, actual: level });
      return;
    }
    (req as any).principal = claims;
    next();
  };
}

function iamRequestMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Service-Id', SERVICE_ID);
  res.setHeader('X-Mesh-Address', MESH_ADDRESS);
  res.setHeader('X-IAM-Version', '1.0');
  next();
}

function iamHealthStatus() {
  return {
    iam: {
      version: '1.0', algorithm: IAM_ALGORITHM,
      status: IAM_JWT_SECRET ? 'configured' : 'unconfigured',
      meshAddress: MESH_ADDRESS,
      routingProtocol: process.env.MESH_ROUTING_PROTOCOL || 'static_port',
      cryptoMigrationPath: 'hmac_sha512 → ml_kem (2030) → hybrid_pqc (2040) → slh_dsa (2060)',
    },
  };
}
// ============================================================================
// END IAM MIDDLEWARE
// ============================================================================

// ── Bootstrap ──────────────────────────────────────────────────────────────

const app = express();
export const crypto = new CryptoEngine();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('combined', {
  stream: { write: (msg: string) => logger.info(msg.trim()) },
}));

// ── Helpers ────────────────────────────────────────────────────────────────

function ok(res: Response, data: unknown, status = 200): void {
  res.status(status).json({ success: true, data, timestamp: new Date().toISOString() });
}

function fail(res: Response, message: string, status = 400): void {
  res.status(status).json({ success: false, error: message, timestamp: new Date().toISOString() });
}

function wrap(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => fn(req, res).catch(next);
}

// ── Health ─────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  const posture = crypto.getSecurityPosture();
  ok(res, {
    status: 'healthy',
    service: 'renik-ai',
    uptime: process.uptime(),
    riskLevel: posture.riskLevel,
  });
});

app.get('/metrics', (_req, res) => {
  const posture = crypto.getSecurityPosture();
  ok(res, {
    ...posture,
    memory: process.memoryUsage(),
    uptime: process.uptime(),
  });
});

// ── Keys ───────────────────────────────────────────────────────────────────

// GET /keys — list all keys
app.get('/keys', (req, res) => {
  const { algorithm, purpose, status } = req.query;
  const keys = crypto.getKeys({
    algorithm: algorithm as KeyAlgorithm | undefined,
    purpose: purpose as KeyPurpose | undefined,
    status: status as KeyStatus | undefined,
  });
  // Strip raw key material from list response
  const safe = keys.map(({ keyMaterial: _km, ...k }) => k);
  ok(res, { keys: safe, count: safe.length });
});

// GET /keys/:id — get a specific key (no raw material)
app.get('/keys/:id', (req, res) => {
  const key = crypto.getKey(req.params.id);
  if (!key) return fail(res, 'Key not found', 404);
  const { keyMaterial: _km, ...safe } = key;
  ok(res, safe);
});

// POST /keys — generate a new key
app.post('/keys', (req, res) => {
  const { name, algorithm, purpose, expiresInDays, owner, tags } = req.body;
  if (!name || !algorithm || !purpose) {
    return fail(res, 'name, algorithm, purpose are required');
  }
  const validAlgorithms: KeyAlgorithm[] = ['AES-256', 'RSA-2048', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384', 'Ed25519'];
  if (!validAlgorithms.includes(algorithm)) {
    return fail(res, `algorithm must be one of: ${validAlgorithms.join(', ')}`);
  }
  const validPurposes: KeyPurpose[] = ['encryption', 'signing', 'authentication', 'key_exchange'];
  if (!validPurposes.includes(purpose)) {
    return fail(res, `purpose must be one of: ${validPurposes.join(', ')}`);
  }
  try {
    const key = crypto.generateKey({ name, algorithm, purpose, expiresInDays, owner, tags });
    const { keyMaterial: _km, ...safe } = key;
    ok(res, safe, 201);
  } catch (err) {
    fail(res, (err as Error).message);
  }
});

// POST /keys/:id/rotate — rotate a key
app.post('/keys/:id/rotate', (req, res) => {
  const { requestedBy } = req.body;
  if (!requestedBy) return fail(res, 'requestedBy is required');
  try {
    const newKey = crypto.rotateKey(req.params.id, requestedBy);
    const { keyMaterial: _km, ...safe } = newKey;
    ok(res, safe);
  } catch (err) {
    fail(res, (err as Error).message, 404);
  }
});

// POST /keys/:id/revoke — revoke a key
app.post('/keys/:id/revoke', (req, res) => {
  const { requestedBy } = req.body;
  if (!requestedBy) return fail(res, 'requestedBy is required');
  const key = crypto.revokeKey(req.params.id, requestedBy);
  if (!key) return fail(res, 'Key not found', 404);
  const { keyMaterial: _km, ...safe } = key;
  ok(res, safe);
});

// ── Certificates ───────────────────────────────────────────────────────────

// GET /certificates — list all certificates
app.get('/certificates', (req, res) => {
  const { status } = req.query;
  const certs = crypto.getCertificates(status as CertStatus | undefined);
  ok(res, { certificates: certs, count: certs.length });
});

// GET /certificates/:id — get a specific certificate
app.get('/certificates/:id', (req, res) => {
  const cert = crypto.getCertificate(req.params.id);
  if (!cert) return fail(res, 'Certificate not found', 404);
  ok(res, cert);
});

// POST /certificates — issue a certificate
app.post('/certificates', (req, res) => {
  const { subject, issuer, keyId, validityDays, sans, requestedBy } = req.body;
  if (!subject || !issuer || !keyId || !requestedBy) {
    return fail(res, 'subject, issuer, keyId, requestedBy are required');
  }
  try {
    const cert = crypto.issueCertificate({
      subject,
      issuer,
      keyId,
      validityDays: validityDays ? Number(validityDays) : undefined,
      sans,
      requestedBy,
    });
    ok(res, cert, 201);
  } catch (err) {
    fail(res, (err as Error).message);
  }
});

// POST /certificates/:id/revoke — revoke a certificate
app.post('/certificates/:id/revoke', (req, res) => {
  const { requestedBy } = req.body;
  if (!requestedBy) return fail(res, 'requestedBy is required');
  const cert = crypto.revokeCertificate(req.params.id, requestedBy);
  if (!cert) return fail(res, 'Certificate not found', 404);
  ok(res, cert);
});

// ── Hashing ────────────────────────────────────────────────────────────────

// POST /hash — compute a hash
app.post('/hash', (req, res) => {
  const { input, algorithm, requestedBy } = req.body;
  if (!input) return fail(res, 'input is required');
  const validAlgorithms: HashResult['algorithm'][] = ['sha256', 'sha512', 'md5'];
  if (algorithm && !validAlgorithms.includes(algorithm)) {
    return fail(res, `algorithm must be one of: ${validAlgorithms.join(', ')}`);
  }
  const result = crypto.computeHash(input, algorithm, requestedBy);
  ok(res, result);
});

// POST /hash/verify — verify a hash
app.post('/hash/verify', (req, res) => {
  const { input, expectedHash, algorithm } = req.body;
  if (!input || !expectedHash) return fail(res, 'input, expectedHash are required');
  const valid = crypto.verifyHash(input, expectedHash, algorithm);
  ok(res, { valid, input, expectedHash, algorithm: algorithm ?? 'sha256' });
});

// ── Security Posture ───────────────────────────────────────────────────────

// GET /posture — security posture assessment
app.get('/posture', (_req, res) => {
  ok(res, crypto.getSecurityPosture());
});

// ── Audit Log ──────────────────────────────────────────────────────────────

// GET /audit — audit log
app.get('/audit', (req, res) => {
  const limit = req.query.limit ? Number(req.query.limit) : 100;
  const entries = crypto.getAuditLog(limit);
  ok(res, { entries, count: entries.length });
});

// ── Stats ──────────────────────────────────────────────────────────────────

app.get('/stats', (_req, res) => {
  ok(res, crypto.getSecurityPosture());
});


// ═══════════════════════════════════════════════════════════════════════════════
// 2060 SMART RESILIENCE LAYER — Auto-wired by Trancendos Compliance Engine
// ═══════════════════════════════════════════════════════════════════════════════
import {
  SmartTelemetry,
  SmartEventBus,
  SmartCircuitBreaker,
  telemetryMiddleware,
  adaptiveRateLimitMiddleware,
  createHealthEndpoint,
  setupGracefulShutdown,
} from '../middleware/resilience-layer';

// Initialize 2060 singletons
const telemetry2060 = SmartTelemetry.getInstance();
const eventBus2060 = SmartEventBus.getInstance();
const circuitBreaker2060 = new SmartCircuitBreaker(`${SERVICE_ID}-primary`, {
  failureThreshold: 5,
  resetTimeoutMs: 30000,
  halfOpenMaxAttempts: 3,
});

// Wire telemetry middleware (request tracking + trace propagation)
app.use(telemetryMiddleware);

// Wire adaptive rate limiting (IAM-level aware)
app.use(adaptiveRateLimitMiddleware);

// 2060 Enhanced health endpoint with resilience status
app.get('/health/2060', createHealthEndpoint({
  serviceName: SERVICE_ID,
  meshAddress: MESH_ADDRESS,
  getCustomHealth: () => ({
    circuitBreaker: circuitBreaker2060.getState(),
    eventBusListeners: eventBus2060.listenerCount(),
    telemetryMetrics: telemetry2060.getMetricNames().length,
  }),
}));

// Prometheus text format metrics export
app.get('/metrics/prometheus', (_req: any, res: any) => {
  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(telemetry2060.exportPrometheus());
});

// Emit service lifecycle events
eventBus2060.emit('service.2060.wired', {
  serviceId: SERVICE_ID,
  meshAddress: MESH_ADDRESS,
  timestamp: new Date().toISOString(),
  features: ['telemetry', 'rate-limiting', 'circuit-breaker', 'event-bus', 'prometheus-export'],
});

// ═══════════════════════════════════════════════════════════════════════════════
// END 2060 SMART RESILIENCE LAYER
// ═══════════════════════════════════════════════════════════════════════════════

// ── Error Handler ──────────────────────────────────────────────────────────

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error({ err }, 'Unhandled error');
  fail(res, err.message || 'Internal server error', 500);
});

export { app };