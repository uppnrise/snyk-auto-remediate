import { describe, it, expect } from 'vitest';
import { logger } from '../../../src/utils/logger.js';

describe('logger', () => {
  it('should have all required log methods', () => {
    expect(typeof logger.debug).toBe('function');
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.warn).toBe('function');
    expect(typeof logger.error).toBe('function');
  });

  it('should not throw when logging strings', () => {
    expect(() => logger.info('test message')).not.toThrow();
    expect(() => logger.warn('warning message')).not.toThrow();
    expect(() => logger.error('error message')).not.toThrow();
    expect(() => logger.debug('debug message')).not.toThrow();
  });

  it('should not throw when logging objects', () => {
    expect(() => logger.info('with object', { key: 'value' })).not.toThrow();
  });
});
