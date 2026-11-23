# Session 04 — Whitelist anti-bot honeypot — exit only for `canSale` addresses

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control (whitelist trap)  
> **Verdict:** `malicious`  
> **Confidence:** High for the source-level gate; deployment state not tested  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`honeypot/session-04-whitelist-antibot-honeypot.sol`](../../contracts/honeypot/session-04-whitelist-antibot-honeypot.sol) |
| Pragma | `^0.5.17` |
| Lines | 693 |
| SHA-256 | `76e4b479ef07d8f43dd8f23bd6373e3e9d27570d1739fd7d25fe41e057d1fa27` |
| Family | Malicious hidden control (whitelist trap) |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

The conspicuous name is accurate: `ensure` exempts `owner`, `tradeAddress`, and addresses in `canSale`; everyone else must satisfy `condition`. The three sale-limit fields are never assigned, so `condition` returns false for all non-exempt senders. Owner/A/P/_adm can mint balances and whitelist addresses. This is a whitelist exit trap, not an anti-bot heuristic that becomes safe after launch.

## What a user experiences

A buyer can receive tokens when the pair/owner is exempt on the source side. A normal holder's `transfer` and `transferFrom` both route through `transferFrom` and `ensure`; without `canSale[holder]`, the call reverts. The owner and designated trade address can exit. The 'anti-bot' framing is a cover for an owner-controlled allowlist.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| Deployer `owner` | Exempt in `ensure`; can `approveAndCall` and `transferownership` | lines 409, 616-623, 631-639 | Deployment owner; `owner` is private |
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | Can overwrite balances/whitelist via `approveAndCall` and set `tradeAddress` via `checkAddress` | lines 614-627, 540-551 | Direct hard-coded literal |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts role chain through `setUsdtPair` | lines 371-380, 423-429 | Direct |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `onlypublic`: `transferTo`, `viewAddress`, `adjust` | `publics` 583-601; modifiers 647-653 | Assembled literal |
| `_adm` | `approval` overwrites a balance and sets `canSale` | lines 439-447, 382-388 | Reached through B → `_usdtPair` → `_user` → `_mod` → `_adm` |
| `tradeAddress` | Exempt from the whitelist gate | line 409; set at 433, 547, 635 | Set by P, A, or owner; unset by default |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Allowlist exit gate | `ensure` 405-419; `condition` 555-581 | Only owner, tradeAddress, or `canSale[from]` bypass `condition` | All other sellers revert |
| Never-initialized sale limits | declarations 608-612 | `_saleNum`, `_minSale`, `_maxSale` have no writes | `condition` returns false at line 557 for every non-exempt caller |
| Overwrite credits and whitelist | `_computing` 363-369; `_approvals` 382-388; `_approvecall` 490-496 | `balanceOf[spender] = value * 10**decimals`; `canSale[spender] = true` | Creates balance and exit permission together |
| Double credit | `_transferTo` 390-401 | Two credits; called by P-gated `transferTo` | Supply/ledger divergence |
| Trade address switch | `viewAddress` 431-437; `checkAddress` 540-551 | P or A can replace the exempt trade address | The set of addresses allowed to exit is mutable |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `transfer` | public, but calls `transferFrom` | Same `ensure` gate as a sale | lines 357-361 |
| `transferFrom` | allowance if caller is not sender; `ensure` | Non-whitelisted holder reverts | lines 451-480 |
| `approveAndCall` | owner or A | Sets a balance and `canSale[spender] = true` | lines 614-627 |
| `approval` | `_adm` | Same overwrite/whitelist helper through `_approvals` | lines 439-447 |
| `adjust` | P | Overwrite/whitelist through `_computing` | lines 482-488, 363-369 |
| `transferownership` | `owner` | Renames/changes `tradeAddress`, not token ownership | lines 631-639 |

## Ledger and invariant notes

- For every non-exempt `from`, `condition` is false because all three limit variables remain zero.
- `canSale` is the only per-address exit permission.
- `totalSupply` is set only in the constructor; overwrite credits do not change it.
- The `owner` variable is private and is not the same as `tradeAddress`.

## Arithmetic notes

- `condition`: `_saleNum == 0 && _minSale == 0 && _maxSale == 0` → `false` (line 557).
- Overwrite credit: balance becomes `addedValue * 10**18` at `decimals = 18`.
- Double credit +2a for P `transferTo`; supply +0.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `An `ensure` function that returns true for owner/trade address/`canSale` and otherwise requires a condition.` | Read the cited source path before treating this as malicious. |
| `condition` has an early return false when all three limits are zero. | Read the cited source path before treating this as malicious. |
| `canSale[addr] = true` paired with `balanceOf[addr] = …`. | Read the cited source path before treating this as malicious. |
| `A function named `transferownership` that writes `tradeAddress`.` | Read the cited source path before treating this as malicious. |
| `transfer` implemented as `transferFrom(msg.sender, to, value)`. | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. On a fork, set the pair as `tradeAddress`; buy, then attempt a sell from a non-whitelisted buyer; expect revert in `condition`.
1. Set `canSale[buyer] = true` through an authorized path, then retry the sell; record the delta.
1. Call `transferownership(newAddr)` and confirm the token `owner` is unchanged.
1. Read `_saleNum`, `_minSale`, `_maxSale` via storage inspection; expect zero and no setter.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- The file contains an unused ERC20 implementation; do not attribute its `_mint` to the deployed DevToken surface.

## Errata for prior documentation

- Prior docs say this contract has no pragma; source line 1 is `pragma solidity ^0.5.17;`.
- The label 'anti-bot' is misleading: the actual effect is a whitelist exit gate with unset limits, not a bonding-curve or cooldown heuristic.
- The inherited-looking `ERC20` contract is not a base of `DevToken`; only the DevToken functions are the token surface.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 05 — Blacklist + detector-proof honeypot — hard-coded owner and mint paths](session-05-blacklist-detector-proof-honeypot.md)
- [Session 07 — Whitelist-switchable honeypot — fee exemptions, not an exit whitelist](session-07-whitelist-switchable-honeypot.md)

## Source

The canonical repository copy is [`honeypot/session-04-whitelist-antibot-honeypot.sol`](../../contracts/honeypot/session-04-whitelist-antibot-honeypot.sol). Its SHA-256 is `76e4b479ef07d8f43dd8f23bd6373e3e9d27570d1739fd7d25fe41e057d1fa27`. The same bytes are copied under [`contracts/honeypot/session-04-whitelist-antibot-honeypot.sol`](../../contracts/honeypot/session-04-whitelist-antibot-honeypot.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
