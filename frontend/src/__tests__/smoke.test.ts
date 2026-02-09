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

describe('Bridge contracts', () => {
  it('exports all contract interfaces via barrel', async () => {
    const bridge = await import('../bridge');
    expect(bridge.validateResponse).toBeDefined();
    expect(typeof bridge.validateResponse).toBe('function');
  });

  it('validateResponse warns on missing keys', async () => {
    const { validateResponse } = await import('../bridge/validators');
    const warns: string[] = [];
    const originalWarn = console.warn;
    console.warn = (msg: string) => warns.push(msg);

    validateResponse({ foo: 1 }, 'TestContract', ['foo', 'bar']);
    expect(warns.length).toBe(1);
    expect(warns[0]).toContain('missing keys');
    expect(warns[0]).toContain('bar');

    console.warn = originalWarn;
  });

  it('validateResponse passes clean data through', async () => {
    const { validateResponse } = await import('../bridge/validators');
    const data = { a: 1, b: 2 };
    const result = validateResponse(data, 'Test', ['a', 'b']);
    expect(result).toBe(data);
  });
});
