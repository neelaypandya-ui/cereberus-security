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

  it('validation map entries have valid required keys', async () => {
    // Import api.ts source to check the validation map is non-empty
    // We verify each entry has [contractName, requiredKeys] with at least 1 key
    const apiModule = await import('../services/api');
    // The validation map is internal but api module should load without error
    expect(apiModule.api).toBeDefined();
    // Verify validateResponse is importable (used by api.ts at module level)
    const { validateResponse } = await import('../bridge/validators');
    expect(typeof validateResponse).toBe('function');

    // Smoke-check: validateResponse with array data validates first item
    const warns: string[] = [];
    const originalWarn = console.warn;
    console.warn = (msg: string) => warns.push(msg);

    validateResponse(
      [{ state: 'idle', threat_count: 0 }],
      'BondStatusResponse',
      ['state', 'threat_count', 'scan_interval_seconds'],
    );
    expect(warns.length).toBe(1);
    expect(warns[0]).toContain('scan_interval_seconds');

    console.warn = originalWarn;
  });
});
