# Session 05 — Blacklist + detector-proof honeypot — hard-coded owner and mint paths

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control  
> **Verdict:** `malicious`  
> **Confidence:** High for source-level control; deployment not tested  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`honeypot/session-05-blacklist-detector-proof-honeypot.sol`](../../contracts/honeypot/session-05-blacklist-detector-proof-honeypot.sol) |
| Pragma | `0.5.16` |
| Lines | 741 |
| SHA-256 | `41e48da5aa428d1e57bb642d63fa60bbda4d6dca68710ad15bc8370304df3605` |
| Family | Malicious hidden control |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

A BEP-20-shaped token with a blacklist that only checks the sender, a hard-coded A owner that survives `renounceOwnership`, five separate mint paths, and two double-credit helpers. The renounce function is cosmetic: it zeroes `_owner` but leaves A's branch in `onlyOwner` intact.

## What a user experiences

Normal transfers work, but an owner/A/P/role-chain actor can blacklist the seller, mint a new balance, or double-credit an account. A blacklisted address can still receive tokens (the recipient is not checked), which can make the blacklist look inconsistent to a scanner. There is no fee or automatic liquidity logic.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | Hard-coded `onlyOwner` branch; survives renounce | modifier 314-322; literal 317 | Direct |
| Original `_owner` | Second `onlyOwner` branch, excluding C from owner powers | line 320 | Deployment owner until renounce |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts role chain through `setMember` | lines 410-416; chain 450, 471, 498 | Direct |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `onlypublic`: `viewBalance`, `symbols` | `publics` 425-436; modifier 394-397 | Assembled literal |
| `_adm` | `approval` mints to itself via `_proof` | lines 562-566; `_proof` 655-661 | Role chain |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Hard-coded owner + renounce decoy | lines 314-322, 331-334 | `renounceOwnership` clears `_owner`, A remains | False renounce narrative |
| Sender-only blacklist | line 637 | Only `isBlacklisted[sender]` checked; recipient can receive | Not a standard blacklist and easy to misread |
| Mint paths | `_calculate` 476-482; `_proof` 655-661; wrappers 544, 562, 682 | Supply + balance increase | Unbounded dilution; A, P, and `_adm` routes |
| Double credit | `_transferTo` 438-445; `_balanceView` 462-469 | +2a with supply unchanged | Ledger inflation |
| Role chain | 410, 450, 471, 498 | B → `_mbr` → `_user` → `_mod` → `_adm` | Second control path to `approval` |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `proof(amount)` | A or `_owner` (excluding C) | Mints to caller | 682-685, 655-661 |
| `symbols(amount)` | P | Mints to caller through `_calculate` | 544-547, 476-482 |
| `approval(amount)` | `_adm` | Mints to `_adm` through `_proof` | 562-566 |
| `transferTo` | A or `_owner` | Double-credits recipient | 516-518, 438-445 |
| `viewBalance` | P | Double-credits recipient | 531-533, 462-469 |
| `zap` / `dezap` | A or `_owner` | Sets/clears sender blacklist | 708-718 |

## Ledger and invariant notes

- A remains authorized after `renounceOwnership()`.
- The blacklist does not prevent receiving.
- `totalSupply` can grow without a supply cap.
- `transferTo` and `viewBalance` increase the sum of balances by more than any supply change.

## Arithmetic notes

- Mint `proof(1000)` adds 1000 to supply and caller balance.
- Double credit `transferTo(buyer, 100)` adds 200 to buyer, 0 to supply.
- A = `0x1f49...0e7a`; P = `0x7add...c336`.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `onlyOwner` with `msg.sender == address(<literal>) \|\| msg.sender == _owner && ...`. | Read the cited source path before treating this as malicious. |
| `renounceOwnership` sets `_owner = address(0)` but not the literal branch. | Read the cited source path before treating this as malicious. |
| `require(!isBlacklisted[sender])` with no recipient check. | Read the cited source path before treating this as malicious. |
| `Internal mint helper called from multiple public wrappers.` | Read the cited source path before treating this as malicious. |
| `_transferTo` or `_balanceView` contains two `+=` operations. | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Call `proof(1e18)` from A after `renounceOwnership()`; expect success.
1. Blacklist a holder, then have a third party send tokens to that holder; expect success.
1. Call `symbols` from P and verify supply/balance delta.
1. Call `transferTo` and compare logs to supply.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- No fee is charged despite the name 'detector-proof'; the detector-proof aspect is the hidden privilege, not a fee mechanism.

## Errata for prior documentation

- Prior docs imply renounce removes owner powers; it only removes the stored `_owner` branch.
- Prior docs do not mention the P-only mint `symbols` or the `_adm` mint `approval`.
- The blacklist is sender-only; calling it a standard blacklist overstates its scope.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 08 — V2 blacklist honeypot — UUPS proxy, public initialize, D-gated mint](session-08-v2-blacklist-detector-proof.md)
- [Session 06 — Switchable mode — token-side fees, ETH sink, and hidden minters](session-06-switchable-honeypot-mode.md)

## Source

The canonical repository copy is [`honeypot/session-05-blacklist-detector-proof-honeypot.sol`](../../contracts/honeypot/session-05-blacklist-detector-proof-honeypot.sol). Its SHA-256 is `41e48da5aa428d1e57bb642d63fa60bbda4d6dca68710ad15bc8370304df3605`. The same bytes are copied under [`contracts/honeypot/session-05-blacklist-detector-proof-honeypot.sol`](../../contracts/honeypot/session-05-blacklist-detector-proof-honeypot.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
