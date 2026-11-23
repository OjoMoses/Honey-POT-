# Session 8 — Upgraded V2 Blacklist + Detector-Proof Honeypot

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-08-v2-blacklist-detector-proof.sol` |
| Original root file | `Session 1 - Upgraded V2 Blacklist Honeypot Detector Proof.sol` |
| Solidity | `^0.8.24` |
| Length | 741 lines |
| Structural family | 3 (blacklist, BEP-20) |
| Threat classes | T3 T4 T5 T6 T7 T8 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

Session 5 ported to a UUPS-upgradeable layout with a public `initialize`. Control plane and blacklist logic are unchanged.

## How it works

- `initialize(name, symbol, supply, decimals)` is `public`, guarded only by a private `initialized` flag; the first caller becomes owner and receives the supply.
- Imports `UUPSUpgradeable`; upgrade authorisation uses the same owner check that accepts **A**.
- Blacklist, mint and double-credit paths as in Session 5; **D** gates `setMedium`, which stores an extra role slot `_miu`.

## Transfer predicate

As Session 5.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification)

## Detection signals

- No `_disableInitializers()` / constructor guard.
- Upgradeable implementation behind a proxy whose admin you cannot verify.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), 0x63e67a28…4668 (**D**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
