# Session 07 — Whitelist-switchable honeypot — fee exemptions, not an exit whitelist

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control and broken fee accounting  
> **Verdict:** `broken`  
> **Confidence:** High for source-level effects; no execution  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`honeypot/session-07-whitelist-switchable-honeypot.sol`](../../contracts/honeypot/session-07-whitelist-switchable-honeypot.sol) |
| Pragma | `^0.8.0` |
| Lines | 393 |
| SHA-256 | `ed97be16537db1921277290fa82a5e2cc86a218e31b87c9ed28f842ad3111de6` |
| Family | Malicious hidden control and broken fee accounting |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

Session 6 plus an `isFeeExempt` mapping. The word 'whitelist' refers only to fee exemption, not to a transfer allowlist or an anti-bot exit gate. The tax still reads `sellFee` in every `transferFrom`; the owner/A still survive renounce; and the custom buy/sell functions still create ledger credits without a matching supply or ETH payout.

## What a user experiences

A fee-exempt address avoids the `sellFee` deduction in `transferFrom`; a non-exempt holder pays it. This is not a general whitelist that controls who can trade. The public `transfer` path is free, while pair-mediated transfers can be taxed up to 100%.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | `onlyOwner` / `onlyAuthorized`; fee and exemption control | modifiers 301-310, 384-392; literal 304/387 | Direct |
| D = 0x63e67a280645edf97880c1df03c8301b151c4668 | `onlyAuthorize`: transferTo, FeesView, BuySellFee | modifier 197-205; literal 200 | Direct |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts role chain | 96-103; chain 268, 295, 362 | Direct |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `onlypublic`: viewBalance, compute, FeeStructure | 129-140, 250-253 | Assembled literal |
| Fee-exempt set | `isFeeExempt[addr]`; owner can add/remove | 47, 320-330 | Not a trading allowlist |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Fee exemption, not whitelist | 47, 212-215, 320-330 | Skips fee only; no transfer gate | The contract name overstates the mechanism |
| Fee cap 100 | 158-159, 261-262, 285-286, 313-314, 355-356 | 100% tax accepted | Recipient can receive zero |
| Token-side tax | 207-235 | Fee credited to contract; supply unchanged | No ETH or LP routing |
| ETH sink / no-payout functions | buy 332-351; sell 368-382 | Same Session 6 accounting | Not AMM functions |
| Hidden mint routes | 87-93, 121-127, 237-243 | Role-gated supply increase | Dilution |
| Cosmetic renounce | 278-281 | A remains | False renounce |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `setFeeExempt` / `removeFeeExemptStatus` | A or owner | Toggles fee exemption only | 320-330 |
| `transferFrom` | allowance; fee if not exempt | Taxed transfer; fee to contract | 207-235 |
| `buy` / `sell` | public payable / public | Ledger credit or token sink; no ETH payout | 332-351, 368-382 |
| `proof`, `rewire`, `scaling`, `FeesView`, `compute` | A / `_adm` / A-or-D / P | Mint paths | 192-195, 110-114, 172-175, 245-248, 116-119 |
| `LockLPToken` | A or owner | Empty | 292-293 |

## Ledger and invariant notes

- Fee exemption does not imply transfer permission.
- `buyFee` is set but never used by `transferFrom`; only `sellFee` is applied.
- A remains privileged after renounce.
- The token contract accumulates fee tokens with no distribution path.

## Arithmetic notes

- 5% fee on 1000 = 50; recipient gets 950, contract gets 50.
- Fee-exempt 1000 transfer = 1000 to recipient, 0 to contract.
- 100% fee: recipient gets 0; no revert.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `isFeeExempt` mapping used only inside `transferFrom`. | Read the cited source path before treating this as malicious. |
| `No address-list check in `transfer`.` | Read the cited source path before treating this as malicious. |
| `buyFee` assigned but only `sellFee` read in transferFrom. | Read the cited source path before treating this as malicious. |
| `LockLPToken` no-op. | Read the cited source path before treating this as malicious. |
| `Empty/renamed role chain to `_adm`.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Compare `transfer` and `transferFrom` for the same amount and holders.
1. Set a holder exempt; confirm no fee but no other permission change.
1. Set sellFee=100 and verify the recipient receives zero.
1. Check that buyFee does not affect `transferFrom`.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- No whitelist mode switch exists despite the filename; the only address list is fee exemption.

## Errata for prior documentation

- Prior docs describe a 'whitelist switchable' mode; source has only fee exemption and fee rates.
- The filename implies a trading allowlist, but `transfer` is unrestricted.
- The fee is token-denominated, not an ETH buy/sell tax.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 06 — Switchable mode — token-side fees, ETH sink, and hidden minters](session-06-switchable-honeypot-mode.md)
- [Session 09 — V2 whitelist-switchable — UUPS fee token with hidden minters](session-09-v2-whitelist-switchable.md)

## Source

The canonical repository copy is [`honeypot/session-07-whitelist-switchable-honeypot.sol`](../../contracts/honeypot/session-07-whitelist-switchable-honeypot.sol). Its SHA-256 is `ed97be16537db1921277290fa82a5e2cc86a218e31b87c9ed28f842ad3111de6`. The same bytes are copied under [`contracts/honeypot/session-07-whitelist-switchable-honeypot.sol`](../../contracts/honeypot/session-07-whitelist-switchable-honeypot.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
