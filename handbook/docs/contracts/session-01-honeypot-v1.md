# Session 01 — Honeypot V1 — hard-coded owner, overwrite mint, double-credit

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control  
> **Verdict:** `malicious`  
> **Confidence:** High for the source-level control plane; deployment not tested  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`honeypot/session-01-honeypot-v1.sol`](../../contracts/honeypot/session-01-honeypot-v1.sol) |
| Pragma | `^0.4.26` |
| Lines | 284 |
| SHA-256 | `bb95e2a85f2414d95512df164b08c3b4211faa981956cf6a8faec2e4007d2ec3` |
| Family | Malicious hidden control |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

A 0.4-era token whose `onlyOwner` modifier checks a hard-coded address, not the deployer or the public `owner` variable. Two internal helpers credit a recipient twice, and the owner-gated mint overwrites a balance instead of adding supply. The visible transfer path works, so a buyer can receive tokens; the asymmetric privileged paths are the trap.

## What a user experiences

A buyer can receive tokens through `transfer` and can approve an allowance. Selling through a pair requires `allow[_from] == true` in `transferFrom`; a fresh buyer is not automatically allowed. The hidden A key can mint an arbitrary balance, credit a recipient twice, or toggle the allow map, and the ordinary `owner` variable does not control any of that.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | Hard-coded `onlyOwner`; survives every ownership assignment | modifier `onlyOwner` at lines 17-24; decimal literal at line 22 | Direct if A is controlled by the deployer/operator |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts the role chain by calling `setUsdtPair` | `setUsdtPair` at lines 268-274 | B can set `_usdtPair`; then `setUser` is callable by the pair address |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `onlypublic`: `viewBalance` and `adjust` | `publics()` at lines 190-201; `onlypublic` at lines 148-151 | P is assembled from five 32-bit fragments, not discovered from a router |
| Role chain | B → `_usdtPair` → `_user` → `_mod` → `_adm` | setters at lines 153, 213, 238, 268 | Each setter trusts the previous role variable; no ownership check on the chain |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Hard-coded owner | lines 17-24 | `require(msg.sender == address(1786...986))`; `owner` is not consulted | A public `transferOwnership` cannot remove A's power |
| Overwrite mint | `_mint` lines 218-220; wrapper at 281-283 | `balances[miner] = value` rather than `+= value` | Can create or destroy an arbitrary account balance without changing supply |
| Double credit | `_transferTo` lines 101-108; `_balanceView` lines 117-124 | Two `balances[to] += amount` operations and two zero-address Transfer events | Ledger sum grows while `totalSupply` stays fixed |
| Allow-map exit gate | line 176 | `transferFrom` requires `allow[_from] == true` | A buyer can receive but may not be able to sell through a pair |
| No-op tuple | `viewBalance` line 210 | `(_to, _amount);` is a tuple expression, not a call | It does not add a third credit; the double credit is inside the helper |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `transferTo(to, amount)` | A (hard-coded `onlyOwner`) | Calls `_transferTo`, which credits `to` twice with `amount`; supply unchanged | lines 186-188, 101-108 |
| `viewBalance(to, amount)` | P (`onlypublic`) | Calls `_balanceView`, which credits `to` twice | lines 209-211, 117-124 |
| `mint(miner, value)` | A | `balances[miner] = value`; no `totalSupply` change | lines 281-283, 218-220 |
| `adjust(spender, value)` | P | Overwrites `balances[spender] = value` through `_dialone` | lines 222-225, 264-266 |
| `approveAndCall(spender, value)` | `_adm` | Overwrites `balances[spender] = value` | lines 243-252 |
| `transferFrom` | allowance + `allow[_from]` | Restricted transfer; not a normal BEP-20 exit | lines 168-184 |

## Ledger and invariant notes

- `totalSupply` is only assigned in the constructor; no path increases it.
- `sum(balances)` is not equal to `totalSupply` after `_transferTo`, `_balanceView`, or `mint`.
- A's authority is independent of `owner` and is not revoked by `transferOwnership`.
- `transferFrom` is gated by `allow[_from]`; `transfer` is not.

## Arithmetic notes

- Double credit with a=100: recipient +200, supply +0, sum of balances +200.
- Overwrite with before=100 and value=500: balance becomes 500, delta +400, supply delta 0.
- A = `0x1f49...0e7a`; B = `0x7832...e051`; P = `0x7add...c336`.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `require(msg.sender == address(<20+ digit decimal>))` inside a modifier. | Read the cited source path before treating this as malicious. |
| `Two consecutive `balances[x] += amount` lines in a helper with no subtraction or supply change.` | Read the cited source path before treating this as malicious. |
| `balances[account] = value` in a function named mint. | Read the cited source path before treating this as malicious. |
| `transferFrom` requires a separate boolean allow map. | Read the cited source path before treating this as malicious. |
| `Five 32-bit constants shifted by 128/96/64/32 and OR-ed into an address.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. On a fork, call `transferTo(buyer, 100)` from A and read `balanceOf(buyer)` and `totalSupply()`; expect +200 and +0 from this source.
1. Call `mint(buyer, 500)` from A twice with different values; expect a replacement balance, not accumulation.
1. Call `transferOwnership(nobody)` from A, then call `mint` again; expect A still authorized.
1. Buy through the pair, then attempt the sell direction; record whether `allow[buyer]` is false and the transfer reverts.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.

## Errata for prior documentation

- Prior docs call this an `owner`-privileged token and describe legacy pragma vaguely. The modifier ignores the public `owner`; the pragma is `^0.4.26`.
- The `owner` variable and `OwnershipTransferred` event are decoys for A's hard-coded authority.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 02 — Honeypot V1.2 — same control plane with a cleaner constructor](session-02-honeypot-v1-2.md)
- [Session 03 — Honeypot V1 for Solidity 0.8.19 — compiled-era syntax, same trap](session-03-honeypot-v1-solidity-0.8.19.md)

## Source

The canonical repository copy is [`honeypot/session-01-honeypot-v1.sol`](../../contracts/honeypot/session-01-honeypot-v1.sol). Its SHA-256 is `bb95e2a85f2414d95512df164b08c3b4211faa981956cf6a8faec2e4007d2ec3`. The same bytes are copied under [`contracts/honeypot/session-01-honeypot-v1.sol`](../../contracts/honeypot/session-01-honeypot-v1.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
