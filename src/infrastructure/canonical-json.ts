// Deterministic JSON serialization: object keys are always sorted, so two
// structurally-identical values hash identically regardless of key
// insertion order. This matters anywhere a hash computed before a value goes
// into Postgres jsonb is later compared against one computed after reading
// it back — jsonb does NOT preserve object key order (it normalizes storage
// order internally), so plain JSON.stringify on a jsonb-round-tripped value
// can silently produce a different string than the one computed on the
// original in-memory object even though the data is identical. Used by
// MeshController's topologyHash, ProductionAgent's topologyHash/firewallHash
// echoes, and NodeReconciliationService's policy-version hash — all of which
// compare a freshly-computed hash against one that passed through
// controller_commands/command_acknowledgements (both jsonb columns).
export const canonicalJson=(value:unknown):string=>{
  if(value===null||typeof value!=="object")return JSON.stringify(value);
  if(Array.isArray(value))return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value as Record<string,unknown>)
    .sort(([a],[b])=>a.localeCompare(b))
    .map(([k,v])=>`${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
};
