# Session 3 — Honeypot Token (V1, Solidity 0.8.19)

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-03-honeypot-v1-solidity-0.8.19.sol` |
| Original root file | `honeypot-smart-contract-0.8.19` |
| Solidity | `^0.8.19` |
| Length | 409 lines |
| Structural family | 1 (allow-list sell gate) |
| Threat classes | T1 T4 T5 T6 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

Port of Session 2 to Solidity ^0.8.19 (constructor keyword, `memory` parameters). Behaviour is unchanged.

## How it works

- SafeMath `assert` checks are retained although 0.8 already reverts on overflow.
- Sell gate, hidden address, role chain and balance writes as in Sessions 1–2.

## Transfer predicate

Same as Session 1.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification)

## Detection signals

- Modern compiler version is not a safety signal: the logic is the same as the 0.4 version.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
