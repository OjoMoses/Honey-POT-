# Session 02 — Honeypot V1.2 — same control plane with a cleaner constructor

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control  
> **Verdict:** `malicious`  
> **Confidence:** High for the source-level control plane; deployment not tested  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`honeypot/session-02-honeypot-v1-2.sol`](../../contracts/honeypot/session-02-honeypot-v1-2.sol) |
| Pragma | `^0.4.26` |
| Lines | 265 |
| SHA-256 | `a076ae965cd1f7b4fcaff83285d7ebb80b3371c8938b807404b8ef1139429f21` |
| Family | Malicious hidden control |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

A near-duplicate of Session 1. `onlyOwner` is still hard-coded to A, `transferFrom` still requires the separate `allow` map, and `mint` still overwrites a balance. The constructor syntax is updated and `setMod` / `setAdm` are present; those changes do not remove the hidden privilege.

## What a user experiences

The public sale path is ordinary, but the exit path through a pair is conditional on an allow flag that A, P, or the role chain can set. The operator can replace a holder's balance or double-credit a chosen account without increasing the reported supply.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | Hard-coded `onlyOwner`; controls mint, transferTo, addAllow | modifier at lines 103-110; literal at line 107 | Direct |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Can set `_usdtPair` | `setUsdtPair` lines 254-260 | B starts the role chain |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `onlypublic` for viewBalance/adjust/Allowances | `publics` lines 181-192 | Assembled literal |
| Role chain | B → `_usdtPair` → `_user` → `_mod` → `_adm` | setters at 149, 204, 229, 254 | Trusts prior role variable |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Hard-coded owner | lines 103-110 | `owner` is set in the constructor but never checked by `onlyOwner` | Ownership transfer is cosmetic with respect to privilege |
| Double credit | `_transferTo` 76-83; `_balanceView` 122-129 | Two credits per helper call | Breaks accounting while supply is fixed |
| Overwrite mint | `_mint` 209-211; wrapper 262-264 | Replacement of a balance | No supply mint is needed to seize value |
| Allow gate | line 167 | `require(allow[_from] == true)` in transferFrom | Exit can be switched off per address |
| Role chain | lines 149, 204, 229, 254 | B-controlled chain to `_adm` | Gives a second operator route to `approveAndCall`/`addAllowance` |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `transferTo` | A | Double-credits recipient | lines 176-178, 76-83 |
| `viewBalance` | P | Double-credits recipient | lines 200-202, 122-129 |
| `mint` | A | Overwrites balance | lines 262-264, 209-211 |
| `adjust` / `approveAndCall` | P / `_adm` | Overwrites a balance via `_dialone` / `_approvals` | lines 213-216, 236-240, 250-252 |
| `transferFrom` | allowance + allow map | Exit gate for pair transfers | lines 163-174 |

## Ledger and invariant notes

- `owner` is assigned but is not the effective owner gate.
- `totalSupply` is fixed after construction.
- `sum(balances)` can exceed or differ from supply after helpers.

## Arithmetic notes

- Same double-credit arithmetic as Session 1: +2a, supply +0.
- Overwrite mint can lower a balance if the supplied value is below the current balance.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `Decimal address gate in modifier.` | Read the cited source path before treating this as malicious. |
| `Two `+=` credits in `_transferTo` / `_balanceView`.` | Read the cited source path before treating this as malicious. |
| `require(allow[_from] == true)` in transferFrom. | Read the cited source path before treating this as malicious. |
| `owner = msg.sender` present but never used in `onlyOwner`. | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Verify `owner()` changes after A calls `transferOwnership`, then confirm `mint` authorization is unchanged.
1. Attempt a sale with `allow[buyer] == false`; expect a revert.
1. Call `transferTo` and compare event count (two Transfer events) to supply delta (zero).

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.

## Errata for prior documentation

- Prior docs describe this as an ownership-controlled token; the effective owner is A, not the `owner` variable.
- The presence of `setMod`/`setAdm` does not make the role chain an ownership mechanism.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 01 — Honeypot V1 — hard-coded owner, overwrite mint, double-credit](session-01-honeypot-v1.md)
- [Session 03 — Honeypot V1 for Solidity 0.8.19 — compiled-era syntax, same trap](session-03-honeypot-v1-solidity-0.8.19.md)

## Source

The canonical repository copy is [`honeypot/session-02-honeypot-v1-2.sol`](../../contracts/honeypot/session-02-honeypot-v1-2.sol). Its SHA-256 is `a076ae965cd1f7b4fcaff83285d7ebb80b3371c8938b807404b8ef1139429f21`. The same bytes are copied under [`contracts/honeypot/session-02-honeypot-v1-2.sol`](../../contracts/honeypot/session-02-honeypot-v1-2.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
