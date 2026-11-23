# Session 15 — Upgraded V2 Automatic Ownership-Renounce Meme Token

| Field | Value |
|---|---|
| Category | token |
| Source file | `contracts/token/session-15-v2-auto-ownership-renounce-meme-token.sol` |
| Original root file | `Session 3 - Upgraded V2 Automatic Ownership Renounce Meme Token.sol` |
| Solidity | `^0.8.0` |
| Length | 90 lines |
| Structural family | Clean |
| Threat classes | — ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Informational** |

## Summary

Session 12 with `name`, `symbol`, `decimals` and `totalSupply` as `constant` and external visibility on interface functions. Not upgradeable despite the “V2” label.

## How it works

- Same constructor-time renounce as Session 12.
- `constant` values are inlined by the compiler, lowering read gas.
- No proxy, no `initialize`, no privileged function.

## Transfer predicate

$P\equiv\text{true}$.

## Equations

—

## Detection signals

- Strictest of the three clean variants: nothing mutable except balances and allowances.

## Hard-coded addresses

None.

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
