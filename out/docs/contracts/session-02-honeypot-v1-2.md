# Session 2 — Honeypot Token (V1.2)

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-02-honeypot-v1-2.sol` |
| Original root file | `honeypot-contract-V1.2` |
| Solidity | `^0.4.26` |
| Length | 265 lines |
| Structural family | 1 (allow-list sell gate) |
| Threat classes | T1 T4 T5 T6 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

Same control flow as Session 1, restructured (declaration order and formatting differ), with an added `showuint160(address)` helper.

## How it works

- Sell gate, role chain and balance writes are identical to [Session 1](session-01-honeypot-v1.md).
- `showuint160(addr)` is a pure helper that returns an address as a `uint160`. The same integer form is what the decimal address literals in the control plane use.
- `onlyOwner` again compares against hard-coded address **A**.

## Transfer predicate

Same as Session 1.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification)

## Detection signals

- Diff against Session 1 shows a restructuring plus the `showuint160` helper; behaviour is unchanged.
- A pure address-to-integer helper in a token contract has no legitimate role and is worth a closer look.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
