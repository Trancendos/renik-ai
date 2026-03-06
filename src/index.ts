/**
 * Renik AI — Entry Point
 *
 * Cryptographic key management, certificate lifecycle, and security
 * posture service for the Trancendos mesh.
 * Zero-cost compliant — no LLM calls, all native crypto operations.
 *
 * Port: 3022
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { app, crypto } from './api/server';
import { logger } from './utils/logger';

const PORT = Number(process.env.PORT ?? 3022);
const HOST = process.env.HOST ?? '0.0.0.0';

// ── Startup ────────────────────────────────────────────────────────────────

async function bootstrap(): Promise<void> {
  logger.info('Renik AI starting up...');

  const server = app.listen(PORT, HOST, () => {
    logger.info(
      { port: PORT, host: HOST, env: process.env.NODE_ENV ?? 'development' },
      '🔐 Renik AI is online — Cryptographic services ready',
    );
  });

  // ── Periodic Security Posture Assessment (every 60 minutes) ─────────────
  const POSTURE_INTERVAL = Number(process.env.POSTURE_INTERVAL_MS ?? 60 * 60 * 1000);
  const postureTimer = setInterval(() => {
    try {
      const posture = crypto.getSecurityPosture();
      logger.info(
        {
          riskLevel: posture.riskLevel,
          totalKeys: posture.totalKeys,
          activeKeys: posture.activeKeys,
          expiredKeys: posture.expiredKeys,
          revokedKeys: posture.revokedKeys,
          totalCertificates: posture.totalCertificates,
          validCertificates: posture.validCertificates,
          expiredCertificates: posture.expiredCertificates,
        },
        '🔐 Renik periodic security posture assessment',
      );

      if (posture.riskLevel === 'critical' || posture.riskLevel === 'high') {
        logger.warn({ riskLevel: posture.riskLevel, recommendations: posture.recommendations }, '⚠️  Security posture requires attention');
      }
    } catch (err) {
      logger.error({ err }, 'Periodic security posture assessment failed');
    }
  }, POSTURE_INTERVAL);

  // ── Graceful Shutdown ────────────────────────────────────────────────────
  const shutdown = (signal: string) => {
    logger.info({ signal }, 'Shutdown signal received');
    clearInterval(postureTimer);
    server.close(() => {
      logger.info('Renik AI shut down cleanly');
      process.exit(0);
    });
    setTimeout(() => {
      logger.warn('Forced shutdown after timeout');
      process.exit(1);
    }, 10_000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    logger.error({ err }, 'Uncaught exception');
    process.exit(1);
  });

  process.on('unhandledRejection', (reason) => {
    logger.error({ reason }, 'Unhandled rejection');
    process.exit(1);
  });
}

bootstrap().catch((err) => {
  logger.error({ err }, 'Bootstrap failed');
  process.exit(1);
});