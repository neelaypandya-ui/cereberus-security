/**
 * Bridge validators — runtime shape validation for API responses.
 */

export function validateResponse<T>(
  data: unknown,
  contractName: string,
  requiredKeys: string[],
): T {
  if (data === null || data === undefined) {
    console.warn(`[Bridge] ${contractName}: received null/undefined response`);
    return data as T;
  }

  if (typeof data === 'object' && !Array.isArray(data)) {
    const obj = data as Record<string, unknown>;
    const missing = requiredKeys.filter((k) => !(k in obj));
    if (missing.length > 0) {
      console.warn(`[Bridge] ${contractName}: missing keys: ${missing.join(', ')}`);
    }
  }

  if (Array.isArray(data) && data.length > 0) {
    const first = data[0];
    if (typeof first === 'object' && first !== null) {
      const obj = first as Record<string, unknown>;
      const missing = requiredKeys.filter((k) => !(k in obj));
      if (missing.length > 0) {
        console.warn(`[Bridge] ${contractName}[]: missing keys in first item: ${missing.join(', ')}`);
      }
    }
  }

  return data as T;
}
