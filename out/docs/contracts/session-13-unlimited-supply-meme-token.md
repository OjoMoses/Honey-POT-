# Session 13 — Unlimited Supply Printing Meme Token

| Field | Value |
|---|---|
| Category | token |
| Source file | `contracts/token/session-13-unlimited-supply-meme-token.sol` |
| Original root file | `unlimited supply printing-normal-meme-token-non honeypot-code` |
| Solidity | `^0.8.0` |
| Length | 827 lines |
| Structural family | 5 (OZ ERC-20 + trade limits) |
| Threat classes | T3 T4 T5 T6 T7 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

Session 10 plus `print(uint256)` (onlyOwner) that mints without limit via `_printbrr`.

## How it works

- `print(amount)` → `_printbrr(msg.sender, amount)` increases `_totalSupply` and the caller's balance with no cap.
- All Session 10 controls remain (blacklist, trade limits, hidden address, role chain, double-credit).

## Transfer predicate

As Session 10.

## Equations

[Math §5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- Public mint named `print` that is `onlyOwner` with no cap or timelock.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
