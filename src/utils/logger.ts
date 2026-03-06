import pino from 'pino';
export const logger = pino({ name: 'renik-ai', level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV !== 'production' ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'SYS:standard' } } : undefined,
  base: { service: 'renik-ai' }, timestamp: pino.stdTimeFunctions.isoTime });
export default logger;
