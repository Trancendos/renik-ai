/**
 * Renik AI — Crypto Security Engine
 *
 * CSO-level security specialist. Manages cryptographic operations,
 * key lifecycle, certificate management, and security auditing.
 * Works alongside Guardian AI (IAM) and Norman AI (intelligence)
 * to form the security triad.
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { v4 as uuidv4 } from 'uuid';
import { createHash, randomBytes } from 'crypto';
import { logger } from '../utils/logger';

// ── Types ─────────────────────────────────────────────────────────────────

export type KeyAlgorithm = 'AES-256' | 'RSA-2048' | 'RSA-4096' | 'ECDSA-P256' | 'ECDSA-P384' | 'Ed25519';
export type KeyStatus = 'active' | 'rotated' | 'revoked' | 'expired';
export type KeyPurpose = 'encryption' | 'signing' | 'authentication' | 'key_exchange';
export type AuditAction = 'key_created' | 'key_rotated' | 'key_revoked' | 'hash_computed' | 'signature_verified' | 'cert_issued' | 'cert_revoked';
export type CertStatus = 'valid' | 'expired' | 'revoked' | 'pending';

export interface CryptoKey {
  id: string;
  name: string;
  algorithm: KeyAlgorithm;
  purpose: KeyPurpose;
  status: KeyStatus;
  keyMaterial: string;    // base64 encoded (simulated)
  fingerprint: string;
  ownerId: string;
  expiresAt?: Date;
  rotatedFrom?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface Certificate {
  id: string;
  subject: string;
  issuer: string;
  keyId: string;
  status: CertStatus;
  serialNumber: string;
  fingerprint: string;
  validFrom: Date;
  validTo: Date;
  createdAt: Date;
}

export interface SecurityAuditEntry {
  id: string;
  action: AuditAction;
  actorId: string;
  targetId: string;
  targetType: 'key' | 'certificate' | 'hash' | 'signature';
  details: Record<string, unknown>;
  timestamp: Date;
}

export interface HashResult {
  input: string;
  algorithm: 'sha256' | 'sha512' | 'md5';
  hash: string;
  computedAt: Date;
}

export interface SecurityPosture {
  activeKeys: number;
  expiringKeys: number;    // expiring within 30 days
  expiredKeys: number;
  revokedKeys: number;
  validCerts: number;
  expiredCerts: number;
  revokedCerts: number;
  recentAuditEvents: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

// ── Crypto Engine ─────────────────────────────────────────────────────────

export class CryptoEngine {
  private keys: Map<string, CryptoKey> = new Map();
  private certificates: Map<string, Certificate> = new Map();
  private auditLog: SecurityAuditEntry[] = [];

  constructor() {
    this.seedSystemKeys();
    logger.info('CryptoEngine (Renik AI) initialized — security posture established');
  }

  // ── Key Management ──────────────────────────────────────────────────────

  generateKey(params: {
    name: string;
    algorithm: KeyAlgorithm;
    purpose: KeyPurpose;
    ownerId: string;
    expiresAt?: Date;
  }): CryptoKey {
    const keyMaterial = randomBytes(32).toString('base64');
    const fingerprint = createHash('sha256').update(keyMaterial).digest('hex').slice(0, 16);

    const key: CryptoKey = {
      id: uuidv4(),
      name: params.name,
      algorithm: params.algorithm,
      purpose: params.purpose,
      status: 'active',
      keyMaterial,
      fingerprint,
      ownerId: params.ownerId,
      expiresAt: params.expiresAt,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.keys.set(key.id, key);
    this.audit('key_created', params.ownerId, key.id, 'key', {
      name: key.name,
      algorithm: key.algorithm,
      purpose: key.purpose,
    });
    logger.info({ keyId: key.id, name: key.name, algorithm: key.algorithm }, 'Cryptographic key generated');
    return key;
  }

  getKey(keyId: string): CryptoKey | undefined {
    return this.keys.get(keyId);
  }

  getKeys(filters?: {
    ownerId?: string;
    status?: KeyStatus;
    purpose?: KeyPurpose;
    algorithm?: KeyAlgorithm;
  }): CryptoKey[] {
    let keys = Array.from(this.keys.values());
    if (filters?.ownerId) keys = keys.filter(k => k.ownerId === filters.ownerId);
    if (filters?.status) keys = keys.filter(k => k.status === filters.status);
    if (filters?.purpose) keys = keys.filter(k => k.purpose === filters.purpose);
    if (filters?.algorithm) keys = keys.filter(k => k.algorithm === filters.algorithm);
    return keys.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  rotateKey(keyId: string, requestedBy: string): CryptoKey {
    const oldKey = this.keys.get(keyId);
    if (!oldKey) throw new Error(`Key ${keyId} not found`);
    if (oldKey.status !== 'active') throw new Error(`Key ${keyId} is not active (status: ${oldKey.status})`);

    // Mark old key as rotated
    oldKey.status = 'rotated';
    oldKey.updatedAt = new Date();

    // Generate new key
    const newKey = this.generateKey({
      name: `${oldKey.name}-rotated`,
      algorithm: oldKey.algorithm,
      purpose: oldKey.purpose,
      ownerId: oldKey.ownerId,
      expiresAt: oldKey.expiresAt
        ? new Date(Date.now() + (oldKey.expiresAt.getTime() - oldKey.createdAt.getTime()))
        : undefined,
    });
    newKey.rotatedFrom = keyId;

    this.audit('key_rotated', requestedBy, keyId, 'key', {
      oldKeyId: keyId,
      newKeyId: newKey.id,
    });
    logger.info({ oldKeyId: keyId, newKeyId: newKey.id, requestedBy }, 'Key rotated');
    return newKey;
  }

  revokeKey(keyId: string, requestedBy: string): CryptoKey | undefined {
    const key = this.keys.get(keyId);
    if (!key) return undefined;
    key.status = 'revoked';
    key.updatedAt = new Date();
    this.audit('key_revoked', requestedBy, keyId, 'key', { reason: 'manual revocation' });
    logger.warn({ keyId, requestedBy }, 'Key revoked');
    return key;
  }

  // ── Certificate Management ──────────────────────────────────────────────

  issueCertificate(params: {
    subject: string;
    keyId: string;
    validityDays?: number;
    issuedBy: string;
  }): Certificate {
    const key = this.keys.get(params.keyId);
    if (!key || key.status !== 'active') {
      throw new Error(`Key ${params.keyId} not found or not active`);
    }

    const validityDays = params.validityDays || 365;
    const validFrom = new Date();
    const validTo = new Date(Date.now() + validityDays * 86400000);
    const serialNumber = randomBytes(8).toString('hex').toUpperCase();
    const fingerprint = createHash('sha256')
      .update(`${params.subject}:${params.keyId}:${serialNumber}`)
      .digest('hex').slice(0, 16);

    const cert: Certificate = {
      id: uuidv4(),
      subject: params.subject,
      issuer: 'renik-ai',
      keyId: params.keyId,
      status: 'valid',
      serialNumber,
      fingerprint,
      validFrom,
      validTo,
      createdAt: new Date(),
    };

    this.certificates.set(cert.id, cert);
    this.audit('cert_issued', params.issuedBy, cert.id, 'certificate', {
      subject: cert.subject,
      validTo: cert.validTo,
    });
    logger.info({ certId: cert.id, subject: cert.subject, validTo: cert.validTo }, 'Certificate issued');
    return cert;
  }

  getCertificate(certId: string): Certificate | undefined {
    return this.certificates.get(certId);
  }

  getCertificates(status?: CertStatus): Certificate[] {
    let certs = Array.from(this.certificates.values());
    if (status) certs = certs.filter(c => c.status === status);
    // Auto-expire
    const now = new Date();
    for (const cert of certs) {
      if (cert.status === 'valid' && cert.validTo < now) {
        cert.status = 'expired';
      }
    }
    return certs.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  revokeCertificate(certId: string, requestedBy: string): Certificate | undefined {
    const cert = this.certificates.get(certId);
    if (!cert) return undefined;
    cert.status = 'revoked';
    this.audit('cert_revoked', requestedBy, certId, 'certificate', { reason: 'manual revocation' });
    logger.warn({ certId, requestedBy }, 'Certificate revoked');
    return cert;
  }

  // ── Hashing ──────────────────────────────────────────────────────────────

  computeHash(input: string, algorithm: HashResult['algorithm'] = 'sha256', requestedBy = 'system'): HashResult {
    const hash = createHash(algorithm).update(input).digest('hex');
    this.audit('hash_computed', requestedBy, hash.slice(0, 8), 'hash', { algorithm, inputLength: input.length });
    return { input: '[redacted]', algorithm, hash, computedAt: new Date() };
  }

  verifyHash(input: string, expectedHash: string, algorithm: HashResult['algorithm'] = 'sha256'): boolean {
    const computed = createHash(algorithm).update(input).digest('hex');
    return computed === expectedHash;
  }

  // ── Security Posture ─────────────────────────────────────────────────────

  getSecurityPosture(): SecurityPosture {
    const keys = Array.from(this.keys.values());
    const certs = Array.from(this.certificates.values());
    const now = new Date();
    const thirtyDays = 30 * 86400000;

    const expiringKeys = keys.filter(k =>
      k.status === 'active' && k.expiresAt && k.expiresAt.getTime() - now.getTime() < thirtyDays
    ).length;

    const expiredKeys = keys.filter(k =>
      k.status === 'active' && k.expiresAt && k.expiresAt < now
    ).length;

    // Auto-expire certs
    for (const cert of certs) {
      if (cert.status === 'valid' && cert.validTo < now) cert.status = 'expired';
    }

    const revokedKeys = keys.filter(k => k.status === 'revoked').length;
    const validCerts = certs.filter(c => c.status === 'valid').length;
    const expiredCerts = certs.filter(c => c.status === 'expired').length;
    const revokedCerts = certs.filter(c => c.status === 'revoked').length;
    const recentAuditEvents = this.auditLog.filter(
      e => Date.now() - e.timestamp.getTime() < 3600000
    ).length;

    let riskLevel: SecurityPosture['riskLevel'] = 'low';
    if (expiredKeys > 0 || expiredCerts > 0) riskLevel = 'medium';
    if (revokedKeys > 2 || expiringKeys > 3) riskLevel = 'high';
    if (expiredKeys > 3) riskLevel = 'critical';

    return {
      activeKeys: keys.filter(k => k.status === 'active').length,
      expiringKeys,
      expiredKeys,
      revokedKeys,
      validCerts,
      expiredCerts,
      revokedCerts,
      recentAuditEvents,
      riskLevel,
    };
  }

  // ── Audit Log ────────────────────────────────────────────────────────────

  getAuditLog(limit = 100): SecurityAuditEntry[] {
    return this.auditLog.slice(-limit).reverse();
  }

  // ── Private ──────────────────────────────────────────────────────────────

  private audit(
    action: AuditAction,
    actorId: string,
    targetId: string,
    targetType: SecurityAuditEntry['targetType'],
    details: Record<string, unknown>
  ): void {
    const entry: SecurityAuditEntry = {
      id: uuidv4(),
      action,
      actorId,
      targetId,
      targetType,
      details,
      timestamp: new Date(),
    };
    this.auditLog.push(entry);
    if (this.auditLog.length > 10000) this.auditLog.shift();
  }

  private seedSystemKeys(): void {
    const systemKeys = [
      { name: 'mesh-signing-key', algorithm: 'ECDSA-P256' as KeyAlgorithm, purpose: 'signing' as KeyPurpose },
      { name: 'mesh-encryption-key', algorithm: 'AES-256' as KeyAlgorithm, purpose: 'encryption' as KeyPurpose },
      { name: 'agent-auth-key', algorithm: 'Ed25519' as KeyAlgorithm, purpose: 'authentication' as KeyPurpose },
    ];
    for (const k of systemKeys) {
      this.generateKey({ ...k, ownerId: 'system', expiresAt: new Date(Date.now() + 365 * 86400000) });
    }
    logger.info({ count: systemKeys.length }, 'System cryptographic keys seeded');
  }
}