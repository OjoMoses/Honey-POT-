# Session 11 — Ownership-Renounce Meme Token

| Field | Value |
|---|---|
| Category | token |
| Source file | `contracts/token/session-11-ownership-renounce-meme-token.sol` |
| Original root file | `ownership renounce-normal-meme-token-non honeypot-code` |
| Solidity | `0.5.16` |
| Length | 588 lines |
| Structural family | Clean |
| Threat classes | — ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Informational** |

## Summary

Standard BEP-20 with SafeMath, `Ownable`, `renounceOwnership`, `transferOwnership`. No hard-coded addresses, no role chain and no externally reachable mint.

## How it works

- `onlyOwner` checks only `_owner == _msgSender()`.
- `_mint` is defined but never called, and no public function exposes it; `_burn` is likewise internal.
- Supply is fixed at construction. Ownership matters only for `transferOwnership` / `renounceOwnership`.

## Transfer predicate

$P\equiv\text{true}$ (plain ERC-20).

## Equations

—

## Detection signals

- Scanner reports no indicators.
- Still verify deployed bytecode matches this source and that the constructor mints the intended supply.

## Hard-coded addresses

None.

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
