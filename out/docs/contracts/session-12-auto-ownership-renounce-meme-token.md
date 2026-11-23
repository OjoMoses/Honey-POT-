# Session 12 — Automatic Ownership-Renounce Meme Token

| Field | Value |
|---|---|
| Category | token |
| Source file | `contracts/token/session-12-auto-ownership-renounce-meme-token.sol` |
| Original root file | `automatic ownership renounce-normal-low gas fee-meme-token-non honeypot-code` |
| Solidity | `^0.8.0` |
| Length | 90 lines |
| Structural family | Clean |
| Threat classes | — ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Informational** |

## Summary

Minimal ERC-20: 1,000,000 tokens minted to the deployer, then `renounceOwnership()` runs inside the constructor. No privileged function remains.

## How it works

- Constructor mints to deployer, emits `Transfer`/`OwnershipTransferred`, then renounces; `owner == address(0)` from block zero of the contract.
- `_transfer` uses `unchecked` arithmetic **after** an explicit balance check, so it cannot underflow.
- `name`, `symbol`, `decimals`, `totalSupply` are `public` storage variables (not `constant`), a small gas cost compared with Session 15.

## Transfer predicate

$P\equiv\text{true}$.

## Equations

—

## Detection signals

- `owner()` returns the zero address at deployment.
- No mint, burn, fee or list functions.

## Hard-coded addresses

None.

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
