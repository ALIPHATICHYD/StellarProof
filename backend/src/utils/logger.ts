 /**
 * Minimal structured logger.
 *
 * In production this should be replaced with Winston / Pino, but this
 * thin wrapper keeps the surface area small and makes log lines easy
 * to grep in CI / CloudWatch.
 */
export const logger = {
  info: (message: string, meta?: Record<string, unknown>): void => {
    console.info(
      JSON.stringify({ level: 'info', timestamp: new Date().toISOString(), message, ...meta }),
    );
  },

  warn: (message: string, meta?: Record<string, unknown>): void => {
    console.warn(
      JSON.stringify({ level: 'warn', timestamp: new Date().toISOString(), message, ...meta }),
    );
  },

  error: (message: string, meta?: Record<string, unknown>): void => {
    console.error(
      JSON.stringify({ level: 'error', timestamp: new Date().toISOString(), message, ...meta }),
    );
  },
};