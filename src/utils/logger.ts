import winston from 'winston';

/**
 * Custom logger for the ZK-KYC wallet implementation
 * Provides structured logging with appropriate levels
 * and sensitive data protection
 */
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'zk-kyc-wallet' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    // In production, you might want to add file transport
    // new winston.transports.File({ filename: 'error.log', level: 'error' }),
    // new winston.transports.File({ filename: 'combined.log' })
  ]
});

/**
 * Sanitize an object to remove sensitive information before logging
 * @param data - The data to sanitize
 * @returns The sanitized data
 */
export function sanitizeForLogging(data: any): any {
  if (!data) return data;
  
  if (typeof data === 'object') {
    // Add proper index signatures to allow string indexing
    const sanitized: { [key: string]: any } = Array.isArray(data) ? [] : {};
    
    for (const key in data) {
      // Skip sensitive fields or truncate long values
      if (['privateKey', 'secret', 'password', 'viewingKey'].includes(key)) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof data[key] === 'string' && data[key].length > 100) {
        sanitized[key] = `${data[key].substring(0, 20)}...`;
      } else if (typeof data[key] === 'object') {
        sanitized[key] = sanitizeForLogging(data[key]);
      } else {
        sanitized[key] = data[key];
      }
    }
    
    return sanitized;
  }
  
  return data;
}

/**
 * Safe logging helper that sanitizes data before logging
 */
export const safeLogger = {
  error: (message: string, data?: any) => {
    logger.error(message, data ? sanitizeForLogging(data) : undefined);
  },
  warn: (message: string, data?: any) => {
    logger.warn(message, data ? sanitizeForLogging(data) : undefined);
  },
  info: (message: string, data?: any) => {
    logger.info(message, data ? sanitizeForLogging(data) : undefined);
  },
  debug: (message: string, data?: any) => {
    logger.debug(message, data ? sanitizeForLogging(data) : undefined);
  }
};

export default safeLogger;
