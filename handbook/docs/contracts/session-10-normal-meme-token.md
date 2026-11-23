# Session 10 — “Normal” meme token — full hidden control plane under an OZ-looking shell

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control (mislabeled as normal)  
> **Verdict:** `malicious`  
> **Confidence:** High for source-level control; deployment not tested  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`token/session-10-normal-meme-token.sol`](../../contracts/token/session-10-normal-meme-token.sol) |
| Pragma | `^0.8.0` |
| Lines | 822 |
| SHA-256 | `e95b55d4259f1561bf605e82c750b4c5b8078b62b0e2e82bef857f0c49fda32a` |
| Family | Malicious hidden control (mislabeled as normal) |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

Despite the filename and prior 'non-honeypot' labels, this is an OpenZeppelin-shaped ERC-20 with a hard-coded A owner, a B-started role chain to `_adm`, and four extra mint/credit routes: `proof`, `approval`, `decimal`, and `transferTo`/`viewBalance`. `reviewRules` is P-gated and can change the pair and holding limits. `renounceOwnership` leaves A in control.

## What a user experiences

Before a pair is set, only the owner can move tokens. After the owner/P sets a pair, ordinary transfers work subject to blacklist and optional min/max holding limits on buys. P can silently change those rules, and privileged actors can mint or double-credit balances at will. The token is not a normal fixed-supply meme token.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | Hard-coded onlyOwner; mint/blacklist/rules/transferTo | modifier 116-127; literal 122 | Direct; survives renounce |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts role chain via `setMember` | 79-93; chain 146, 103, 140 | Direct |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `naming`: `viewBalance`, `decimal`, `reviewRules` | 797-808, 738-741 | Assembled literal |
| `_adm` | `approval` mints | 747-751 | Role chain |
| Current owner | Owner branch, but A remains; can blacklist/rules | 116-127 | Not required for A |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Hard-coded owner | 116-127 | A or current owner, excluding C | A's authority is not revoked |
| Role chain | 79, 146, 103, 140 | B → `_mbr` → `_user` → `_mod` → `_adm` | Second authority path |
| Mint paths | `_proof` 556-562; `approval` 747-751; `proof` 768-771; `_compute` 653-659; `decimal` 810-813 | Supply + balance increase | Dilution |
| Double credit | `_transferTo` 511-518; `_balanceView` 616-623 | +2a, supply +0 | Ledger inflation |
| P-controlled rules | `reviewRules` 790-795 | Changes pair, trade-limited flag, min/max | Can freeze or reshape trading without owner |
| Blacklist + holding limits | `_beforeTokenTransfer` 773-788 | Blocks from/to blacklist; limits buys from pair | Exit/entry controls |
| Initial pair gate | 780-783 | If pair is zero, only owner transfers | Trading can be dormant until operator opens it |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `proof(amount)` | A or owner | Mint to caller | 768-771 |
| `approval(amount)` | `_adm` | Mint to `_adm` | 747-751 |
| `decimal(amount)` | P | Mint to P | 810-813, 653-659 |
| `transferTo(to, amount)` | A or owner | Double-credit `to` | 815-817, 511-518 |
| `viewBalance(to, amount)` | P | Double-credit `to` | 757-759, 616-623 |
| `reviewRules(...)` | P | Changes pair/limits/trade flag | 790-795 |
| `blacklist` | A or owner | Sets from/to blacklist flag | 753-755 |
| `setPrinciplesRules(...)` | A or owner | Changes pair/limits/trade flag | 761-766 |

## Ledger and invariant notes

- `renounceOwnership` clears the stored owner but not A's branch.
- P can change trading rules independently of owner.
- `totalSupply` is mutable through at least four paths.
- `transferTo`/`viewBalance` can break the supply/balance-sum invariant.
- If `LiquiduniswapV2Pair == address(0)`, only owner addresses can transfer.

## Arithmetic notes

- `proof(1e18)` adds 1e18 supply and balance.
- `viewBalance(buyer, 100)` adds 200 to buyer, 0 to supply.
- Holder with 100,000 of 1,000,000 is diluted from 10% to 5% by a 1,000,000 mint.
- Default holding limits are zero; if `tradelimited` is true and max is zero, buys from the pair fail.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `A file named 'normal' with hard-coded decimal addresses and `publics()` assembly.` | Read the cited source path before treating this as malicious. |
| `OZ ERC20 plus non-standard `proof`, `approval`, `decimal`, `transferTo`, `viewBalance`.` | Read the cited source path before treating this as malicious. |
| `reviewRules` gated by a fragment-assembled address, not owner. | Read the cited source path before treating this as malicious. |
| `_beforeTokenTransfer` owner-only branch when pair is zero. | Read the cited source path before treating this as malicious. |
| `Double `+=` in `_transferTo`/`_balanceView`.` | Read the cited source path before treating this as malicious. |
| `onlyOwner` is `(literal \|\| owner() == sender && sender != C)`. | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Deploy with no pair: attempt a non-owner transfer; expect revert.
1. Set pair as owner, buy, then call `reviewRules(tradelimited=true, pair, max=0, min=0)` from P; attempt a buy.
1. Mint via `proof` and `decimal`; compare supply and holder shares.
1. Renounce owner, then call `proof` from A.
1. Blacklist a recipient and a sender separately; confirm both directions are blocked.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- No live pair or token deployment was inspected; 'buy from pair' refers to the source-level `_beforeTokenTransfer` condition, not measured router behavior.

## Errata for prior documentation

- Prior docs label Session 10 'normal/non-honeypot' or merely 'should be audited'; source contains hidden mint, double-credit, role-chain, and P-rule controls.
- The name `_beforeTokenTransfer` is OZ-shaped but the overridden rules are not standard OZ.
- `renounceOwnership` is not a safety feature here.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 13 — Unlimited-supply meme token — Session 10 plus owner `print` mint](session-13-unlimited-supply-meme-token.md)
- [Session 14 — V2 unlimited-supply meme token — UUPS, public initialize, double supply](session-14-v2-unlimited-supply-meme-token.md)
- [Session 12 — Auto-renounce meme token — fixed supply, owner revoked in constructor](session-12-auto-ownership-renounce-meme-token.md)

## Source

The canonical repository copy is [`token/session-10-normal-meme-token.sol`](../../contracts/token/session-10-normal-meme-token.sol). Its SHA-256 is `e95b55d4259f1561bf605e82c750b4c5b8078b62b0e2e82bef857f0c49fda32a`. The same bytes are copied under [`contracts/token/session-10-normal-meme-token.sol`](../../contracts/token/session-10-normal-meme-token.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
