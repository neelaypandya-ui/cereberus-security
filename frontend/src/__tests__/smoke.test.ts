/**
 * Smoke tests — verify core modules are importable and correctly structured.
 */
import { describe, it, expect } from 'vitest';

describe('API module', () => {
  it('exports api object with expected methods', async () => {
    const { api } = await import('../services/api');
    expect(api).toBeDefined();
    expect(typeof api.login).toBe('function');
    expect(typeof api.getMe).toBe('function');
    expect(typeof api.getAlerts).toBe('function');
  });

  it('exports CSRF helpers', async () => {
    const { setCsrfToken, getCsrfToken } = await import('../services/api');
    expect(typeof setCsrfToken).toBe('function');
    expect(typeof getCsrfToken).toBe('function');

    setCsrfToken('test-token');
    expect(getCsrfToken()).toBe('test-token');
    setCsrfToken(null);
    expect(getCsrfToken()).toBeNull();
  });
});
