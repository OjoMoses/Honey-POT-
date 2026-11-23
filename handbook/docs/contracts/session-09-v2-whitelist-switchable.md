# Session 09 — V2 whitelist-switchable — UUPS fee token with hidden minters

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control (upgradeable)  
> **Verdict:** `broken`  
> **Confidence:** High for source-level effects; proxy deployment not tested  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`honeypot/session-09-v2-whitelist-switchable.sol`](../../contracts/honeypot/session-09-v2-whitelist-switchable.sol) |
| Pragma | `^0.8.0` |
| Lines | 401 |
| SHA-256 | `69857f43530e00b5187e4d4cbcdb23d397e21d3c04dcb1e2b71d72deedacd1dd` |
| Family | Malicious hidden control (upgradeable) |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

A UUPS version of the fee-switch family. It has public initialize with no initializer disable, 100%-cap fee setters, fee exemption, token-side tax, custom buy/sell functions with no ETH payout, and A/D/P/_adm mint routes. There is no whitelist or mode switch beyond fee exemption.

## What a user experiences

`transfer` is free; `transferFrom` can tax at `sellFee` up to 100%. Exempt addresses avoid the tax. The custom `buy`/`sell` functions are not AMM operations and leave ETH/tokens in the contract. If proxy initialization is not atomic, the first caller can become owner and receive supply.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | `onlyOwner`/`onlyAuthorized`; upgrade authority | 310-318, 392-400, 80; literal 313/395 | Direct; can upgrade |
| Original `owner` | Second branch; excludes C | 316, 398 | Initialize caller |
| D = 0x63e67a280645edf97880c1df03c8301b151c4668 | `onlyAuthorize`: transferTo, FeesView, BuySellFee | 201-209; literal 204 | Direct |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts role chain | 106-113; chain 281, 304, 370 | Direct |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `onlypublic`: viewBalance, compute, FeeStructure | 139-150, 254-257 | Assembled literal |
| `_adm` | `rewire` mint; fee setting | 120-124, 361-368 | Role chain |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Public initialize | 66-78 | No `_disableInitializers`; first caller owns proxy/implementation | Deployment race |
| Fee cap 100 | 167-168, 270-271, 294-295, 321-322, 363-364 | 100% tax | Full confiscation |
| Fee exemption | 45, 216-218, 328-337 | Skips `sellFee` only | Not a trading whitelist |
| Token-side tax | 211-239 | Fee to contract; supply unchanged | No ETH payout |
| ETH sink / no payout | 340-359, 376-389 | Buy credits; sell sinks; no ETH transfer | Not a sale |
| Mint routes | 98-104, 131-137, 241-247, 249-252 | P/A/`_adm` can inflate supply | Dilution |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `initialize` | public, `!initialized` | Sets owner/feeManager/supply/balance | 66-78 |
| `transferFrom` | allowance; exempt check; sellFee | Taxed transfer | 211-239 |
| `buy` / `sell` | public payable / public | Ledger credit / token sink | 340-359, 376-389 |
| `proof`, `rewire`, `scaling`, `FeesView`, `compute` | A-or-owner / `_adm` / A-or-D / P | Mint | 264-267, 120-124, 182-185, 249-252, 126-129 |
| `setFeeExempt` | A or owner | Fee waiver | 328-337 |
| `LockLPToken` | A or owner | Empty | 301-302 |

## Ledger and invariant notes

- `buyFee` is set but unused by `transferFrom`; only `sellFee` applies.
- Fee exemption is not a transfer allowlist.
- A remains owner after renounce and can upgrade.
- `buy`/`sell` do not pay ETH.

## Arithmetic notes

- 1 ETH buy at 5%: 0.95e18 feeManager, 0.05e18 contract, supply +0, ETH retained.
- 1000 transfer at 100%: recipient 0, contract 1000, no revert.
- 5%/10% round-trip leaves 85.5% before price movement.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `initialize` public with no `_disableInitializers`. | Read the cited source path before treating this as malicious. |
| `_authorizeUpgrade` uses an onlyOwner with a literal branch. | Read the cited source path before treating this as malicious. |
| `100% fee cap and only `sellFee` in transferFrom.` | Read the cited source path before treating this as malicious. |
| `LockLPToken` empty; custom buy/sell with no ETH send. | Read the cited source path before treating this as malicious. |
| `P and `_adm` mint wrappers.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Initialize a proxy twice in a fork; verify first-caller ownership.
1. Set sellFee=100 and confirm zero recipient amount.
1. Call `buy()` with 1 ETH and verify no supply change.
1. Renounce owner, then call `_authorizeUpgrade`/`proof` from A.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- Proxy storage layout and upgrade execution were not tested; no `_disableInitializers` is visible in source.

## Errata for prior documentation

- Prior docs describe a whitelist switch; source only has fee exemption and fee rates.
- Prior docs omit the public initializer and upgrade authority.
- The fee is token-denominated, not an ETH tax routed to the pair.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 06 — Switchable mode — token-side fees, ETH sink, and hidden minters](session-06-switchable-honeypot-mode.md)
- [Session 07 — Whitelist-switchable honeypot — fee exemptions, not an exit whitelist](session-07-whitelist-switchable-honeypot.md)
- [Session 08 — V2 blacklist honeypot — UUPS proxy, public initialize, D-gated mint](session-08-v2-blacklist-detector-proof.md)

## Source

The canonical repository copy is [`honeypot/session-09-v2-whitelist-switchable.sol`](../../contracts/honeypot/session-09-v2-whitelist-switchable.sol). Its SHA-256 is `69857f43530e00b5187e4d4cbcdb23d397e21d3c04dcb1e2b71d72deedacd1dd`. The same bytes are copied under [`contracts/honeypot/session-09-v2-whitelist-switchable.sol`](../../contracts/honeypot/session-09-v2-whitelist-switchable.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
