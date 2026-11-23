# Session 9 — Upgraded V2 Whitelist + Switchable Honeypot

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-09-v2-whitelist-switchable.sol` |
| Original root file | `Session 2 - Upgraded V2 Whitelist Switch On-Off Honeypot Mode.sol` |
| Solidity | `^0.8.0` |
| Length | 401 lines |
| Structural family | 4 (fee switch) |
| Threat classes | T2 T4 T5 T6 T7 T8 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

Session 7 ported to UUPS with `initialize(name, symbol, supply, decimals, feeManager)`; fee switch, fee-exempt list and mint paths unchanged.

## How it works

- `initialize` has the same first-caller-wins weakness as Session 8; `_authorizeUpgrade` is `onlyOwner`.
- `proof` moved below `transferFrom` but is functionally the same as in Session 6.
- Fee ceiling still 100 %.

## Transfer predicate

As Session 7.

## Equations

[Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier)

## Detection signals

- As Sessions 6–8.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), 0x63e67a28…4668 (**D**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
