# Session 4 — Whitelist + Anti-Bot Honeypot

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-04-whitelist-antibot-honeypot.sol` |
| Original root file | `whitelist-antibot-smart-contract` |
| Solidity | `(none in file)` |
| Length | 693 lines |
| Structural family | 2 (anti-bot condition) |
| Threat classes | T1 T5 T6 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

Full ERC-20 stack plus a `DevToken` whose transfers are filtered by `ensure()` / `condition()`. The sell-limit variables have no setter, so `condition` is always false for non-exempt senders.

## How it works

- `transfer` calls `transferFrom(msg.sender, …)`; both are `payable`, which a standard ERC-20 is not.
- `ensure(from,to,v)` passes if `from` or `to` is the owner, `from == tradeAddress`, or `canSale[from]`; otherwise it requires `condition(from, v)`.
- `condition` returns `false` when `_saleNum`, `_minSale` and `_maxSale` are all `0`. A search of the file finds **no assignment** to any of the three, so they stay `0` and the branch always returns `false`.
- `_computing` / `_approvals` set `canSale[x] = true` and *assign* `balanceOf[x] = addedValue × 10^decimals`.
- Role chain starts at `setUsdtPair` (only **B**), then `setUser(_usdtPair)`, `setMod(_user)`, `setAdm(_mod)`.

## Transfer predicate

$P(h,a)=\texttt{condition}(h,a)\equiv\text{false}$ for $h\notin\mathcal{W}$, with $\mathcal{W}=\{\text{owner},\texttt{tradeAddress}\}\cup\{h:\texttt{canSale}[h]\}$.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification)

## Detection signals

- Private limit variables never written.
- `payable` on `transfer`/`approve`.
- Allow-list (`canSale`) set via a function named like an approval.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
