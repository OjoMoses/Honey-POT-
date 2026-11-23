# Session 5 — Blacklist + Detector-Proof Honeypot

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-05-blacklist-detector-proof-honeypot.sol` |
| Original root file | `honeypot-scanner-detector-proof-token` |
| Solidity | `0.5.16` |
| Length | 741 lines |
| Structural family | 3 (blacklist, BEP-20) |
| Threat classes | T3 T4 T5 T6 T7 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

Standards-shaped BEP-20 whose `_transfer` rejects blacklisted senders. Blacklisting is per address and owner-controlled, so it passes any test run from an address that has not been targeted.

## How it works

- `zap(addr)` / `dezap(addr)` (onlyOwner) toggle `isBlacklisted`; `_transfer` reverts with `"Recipient is Gwei"` for a blacklisted **sender**.
- `onlyOwner` accepts **A** or the stored owner (unless it is **C**); `renounceOwnership()` therefore does not remove A's access.
- Mint paths: `proof` (onlyOwner), `approval(uint256)` (`_adm`), `symbols` (`onlypublic`) — all increase supply with no cap.
- `transferTo` / `viewBalance` double-credit.

## Transfer predicate

$P(h)=\lnot\texttt{isBlacklisted}[h]$, writable by privileged callers at any time.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification), [§5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- Fresh-address simulation passes; behaviour changes after a privileged transaction.
- Error string does not match the check it guards.
- Role chain and fragment-assembled address.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
