# Session 06 — Switchable mode — token-side fees, ETH sink, and hidden minters

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control and broken fee accounting  
> **Verdict:** `broken`  
> **Confidence:** High for source-level effects; no execution  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`honeypot/session-06-switchable-honeypot-mode.sol`](../../contracts/honeypot/session-06-switchable-honeypot-mode.sol) |
| Pragma | `^0.8.0` |
| Lines | 369 |
| SHA-256 | `627bedcac0ac2cbe1271d1a9bd2abe1ba4e424ffc5b96c4f243139f0bcd32eff` |
| Family | Malicious hidden control and broken fee accounting |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

The name suggests a switch between normal and honeypot modes, but the code has no whitelist or mode enum. It has configurable fees up to 100%, a `transferFrom` tax that always reads `sellFee`, a `buy()` payable function that credits balances without increasing supply and keeps ETH, a `sell()` that sends tokens to the contract without paying ETH, and several mint routes. A `renounceOwnership` call leaves A's hard-coded branch intact.

## What a user experiences

Plain `transfer` is free; pair-mediated `transferFrom` can be taxed at `sellFee` up to 100%. `buy()` and `sell()` are custom functions that do not perform an AMM trade. Calling `buy()` sends ETH to the contract and credits tokens to `feeManager`/the contract; calling `sell()` moves tokens to the contract but has no ETH payout. The operator can mint through several role-gated paths.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | `onlyAuthorized` and `onlyOwner` branch; fee setting and mints | modifiers 190-198, 290-298, 360-368; literal 193/293/363 | Direct |
| D = 0x63e67a280645edf97880c1df03c8301b151c4668 | `onlyAuthorize` branch; `transferTo`, `FeesView`, `BuySellFee` | modifier 190-198; literal 193 | Direct hard-coded literal |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts role chain through `setMember` | 93-100; chain 257, 284, 338 | Direct |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `onlypublic`: `viewBalance`, `compute`, `FeeStructure` | `publics` 126-137; modifier 239-242 | Assembled literal |
| `_adm` | Can mint via `rewire`; can set fees via `setting` | 107-111, 329-336 | Role chain |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Fee cap 100 | 154-155, 250-251, 274-275, 301-302, 331-332 | 100% is accepted | A 100% tax can confiscate the entire transfer amount |
| Token-side tax | `transferFrom` 200-224 | Fee is credited to the token contract in tokens; supply unchanged | Tax is not paid in ETH or routed to a liquidity pool |
| ETH sink buy | `buy` 308-327 | Credits `feeManager` and contract with ETH base units; no supply increase; ETH stays | Accounting inflation plus unrecoverable ETH |
| No-payout sell | `sell` 344-358 | Deducts user tokens and credits contract; no ETH transfer | Not a sale; it is a token sink |
| Hidden mint routes | `_scale` 85-91; `_proof` 118-124; `_initiate` 226-232 | Supply + balance mint methods exposed through role gates | Dilution and arbitrary balance creation |
| Cosmetic renounce | 267-270 | Clears `owner` but A remains in both privilege modifiers | False safety signal |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `FeeStructure` / `setScale` / `setFees` / `BuySellFee` / `setting` | P / A / D / `_adm` | Set buyFee/sellFee up to 100 | 153-158, 249-255, 273-279, 300-306, 329-336 |
| `transferFrom` | allowance; fee = sellFee | Taxed transfer to recipient; fee to contract | 200-224 |
| `buy()` | public payable | Credits new balances; no supply change; ETH retained | 308-327 |
| `sell(amount)` | public | Moves tokens to contract; no ETH output | 344-358 |
| `proof`, `rewire`, `scaling`, `FeesView`, `compute` | A / `_adm` / A-or-D / P | Mint paths | 185-188, 107-111, 167-170, 234-237, 113-116 |
| `LockLPToken` | A or owner | Empty body; does nothing | 281-282 |

## Ledger and invariant notes

- `buy()` increases the sum of balances without changing totalSupply.
- `sell()` has no ETH transfer.
- `transferFrom` taxes every call by `sellFee`, including calls that are not a DEX sell.
- A remains privileged after `renounceOwnership`.

## Arithmetic notes

- buy 1 ETH at 5%: +0.95e18 to `feeManager`, +0.05e18 to contract, supply +0, ETH +1e18 to contract.
- sell 1000 tokens at 10%: user −1000, contract +900 +100, ETH 0.
- 100% sell: net recipient 0; `_amount.sub(fee)` is 0, not a revert.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `require(newSellFee <= 100)` (not `< 100`). | Read the cited source path before treating this as malicious. |
| `buy()`/`sell()` naming on a token with no router interaction. | Read the cited source path before treating this as malicious. |
| `balanceOf[feeManager] += amount` without a supply increase. | Read the cited source path before treating this as malicious. |
| `LockLPToken()` with an empty body. | Read the cited source path before treating this as malicious. |
| `Hard-coded A/D branches alongside a stored `owner`.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Fork test: call `buy()` with 1 ETH from a fresh account; check ETH balance, token balance, supply, and event count.
1. Set sellFee=100, then call `transferFrom`; verify recipient receives zero and supply is unchanged.
1. Call `renounceOwnership`, then `mint`/`setFees` from A; expect success.
1. Check whether any function sends ETH; source suggests none.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- The name 'switchable honeypot mode' is not backed by a mode switch in source; only fee setters and role gates exist.

## Errata for prior documentation

- Prior docs describe a whitelist/mode switch; no whitelist mapping or mode enum exists. Fees are the only switch.
- The fee is charged in tokens by `transferFrom`, not as an ETH buy/sell tax routed to a pair.
- `LockLPToken` is a no-op; it does not lock liquidity.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 07 — Whitelist-switchable honeypot — fee exemptions, not an exit whitelist](session-07-whitelist-switchable-honeypot.md)
- [Session 09 — V2 whitelist-switchable — UUPS fee token with hidden minters](session-09-v2-whitelist-switchable.md)

## Source

The canonical repository copy is [`honeypot/session-06-switchable-honeypot-mode.sol`](../../contracts/honeypot/session-06-switchable-honeypot-mode.sol). Its SHA-256 is `627bedcac0ac2cbe1271d1a9bd2abe1ba4e424ffc5b96c4f243139f0bcd32eff`. The same bytes are copied under [`contracts/honeypot/session-06-switchable-honeypot-mode.sol`](../../contracts/honeypot/session-06-switchable-honeypot-mode.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
