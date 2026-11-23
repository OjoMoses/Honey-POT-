# Session 6 — Switchable Honeypot Mode

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-06-switchable-honeypot-mode.sol` |
| Original root file | `switch on&off honeypot mode-honeypot-scanner-detector-proof-token` |
| Solidity | `^0.8.0` |
| Length | 369 lines |
| Structural family | 4 (fee switch) |
| Threat classes | T2 T4 T5 T6 T7 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

Token where `transferFrom` takes `sellFee` percent from the amount and `sellFee` may be set anywhere in 0–100 by several privileged paths. At 100 % a seller receives nothing.

## How it works

- `transfer` is fee-free; `transferFrom` charges `fee = amount × sellFee / 100` to the contract. Router sells go through `transferFrom`.
- The fee ceiling is `require(newSellFee <= 100)` — 100 % is allowed. Setters: `setScale` (onlyOwner), `BuySellFee`/`setFees` (onlyAuthorized/Authorize), `setting` (`_adm`), `FeeStructure` (`onlypublic`).
- `buy()` is `payable` but credits `msg.value` **tokens to `feeManager`**, not to the caller, and keeps the ETH; `sell()` moves tokens to the contract and sends **no ETH**. Neither is a market function.
- `LockLPToken()` has an empty body.
- Mint paths (`proof`, `rewire`, `scaling`, `compute`, `FeesView`) and double-credit helpers as in Session 5; `onlyOwner` still accepts **A**; `onlyAuthorize` accepts **D**.

## Transfer predicate

$P\equiv\text{true}$, but received amount is $a\,(1-\tau_s)$ with $\tau_s\in[0,1]$ settable on demand.

## Equations

[Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier)

## Detection signals

- `<= 100` fee ceilings.
- Fee only inside `transferFrom`: wallet transfers show 0 % tax.
- `LockLPToken()` that does nothing.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), 0x63e67a28…4668 (**D**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
