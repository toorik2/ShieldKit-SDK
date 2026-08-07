/**
 * Versioned boundary between the persistent state store and the circuit-input
 * adapter. The store derives this object from authenticated SQLite rows in one
 * short transaction; proving never receives an in-memory history tree.
 */
export const DIRECT_V2_PERSISTENT_PROVING_TRANSITION_SCHEMA =
  "shieldkit-v2-persistent-proving-transition-v1";
