# Session 14 — Upgraded V2 Unlimited Supply Printing Meme Token

| Field | Value |
|---|---|
| Category | token |
| Source file | `contracts/token/session-14-v2-unlimited-supply-meme-token.sol` |
| Original root file | `Session 4 - Upgraded V2 Unlimited Supply Printing Meme Token.sol` |
| Solidity | `^0.8.0` |
| Length | 833 lines |
| Structural family | 5 (OZ ERC-20 + trade limits) |
| Threat classes | T3 T4 T5 T6 T7 T8 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

Session 13 as a UUPS-upgradeable contract: `initialize(name, symbol, supply, decimals)`, `_authorizeUpgrade` is `onlyOwner`.

## How it works

- `initialize` is public with an `initialized` flag; first caller becomes owner and is minted the supply.
- `onlyOwner` accepts **A**, so **A** can authorise upgrades even after the stored owner renounces.
- `print`, blacklist, trade limits, role chain and double-credit helpers as in Session 13.

## Transfer predicate

As Session 10.

## Equations

[Math §5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- Proxy admin and upgrade authority must be treated as full control of the token.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
