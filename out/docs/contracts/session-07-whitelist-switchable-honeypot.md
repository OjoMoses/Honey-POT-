# Session 7 — Whitelist + Switchable Honeypot Mode

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-07-whitelist-switchable-honeypot.sol` |
| Original root file | `whitelist-switch on&off honeypot mode-honeypot-scanner-detector-proof-token` |
| Solidity | `^0.8.0` |
| Length | 393 lines |
| Structural family | 4 (fee switch) |
| Threat classes | T2 T4 T5 T6 T7 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

Session 6 plus an `isFeeExempt` mapping: exempt addresses skip the sell fee, so privileged holders exit at 0 % while ordinary holders can be set to 100 %.

## How it works

- `transferFrom` computes `fee = 0` when `isFeeExempt[_from]`; otherwise `amount × sellFee / 100`.
- `setFeeExempt` / `removeFeeExemptStatus` are `onlyOwner`.
- Everything else matches [Session 6](session-06-switchable-honeypot-mode.md).

## Transfer predicate

$\tau_s(h)=0$ for $h\in\texttt{isFeeExempt}$, $\tau_s(h)=\texttt{sellFee}/100$ otherwise.

## Equations

[Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier)

## Detection signals

- Compare the realised round-trip from exempt and non-exempt addresses.
- `AddressSetFeeExempt` events over time.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), 0x63e67a28…4668 (**D**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
