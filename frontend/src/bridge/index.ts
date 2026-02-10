/**
 * Bridge — Frontend-Backend Integration Layer.
 *
 * Re-exports all contracts and validators for convenient imports:
 *   import { BondStatusResponse, validateResponse } from '../bridge';
 */

export * from './contracts';
export { validateResponse } from './validators';
