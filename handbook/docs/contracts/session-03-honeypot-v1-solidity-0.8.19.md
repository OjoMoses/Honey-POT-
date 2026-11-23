# Session 03 — Honeypot V1 for Solidity 0.8.19 — compiled-era syntax, same trap

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control  
> **Verdict:** `malicious`  
> **Confidence:** High for source-level control; no compiler run  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`honeypot/session-03-honeypot-v1-solidity-0.8.19.sol`](../../contracts/honeypot/session-03-honeypot-v1-solidity-0.8.19.sol) |
| Pragma | `^0.8.19` |
| Lines | 409 |
| SHA-256 | `3f2fd120af2f42b813d85ff01bccdfa1380fa1202e85a7d1d4b817974b12edc0` |
| Family | Malicious hidden control |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

A whitespace-heavy 0.8.19 port of the V1 family. The hard-coded A modifier, allow-map exit gate, overwrite mint, and double-credit helpers survive the port. Checked arithmetic makes the overwrite and double-credit bugs more visible, not harmless.

## What a user experiences

The token presents a standard transfer surface and a larger supply. The operator can still replace any balance or credit a recipient twice; pair sales depend on the allow map. `transferOwnership` only changes the decoy `owner` field.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | Hard-coded `onlyOwner` | lines 160-168; literal at 165 | Direct |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts role chain through `setUsdtPair` | lines 394-402 | Direct |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `onlypublic` viewBalance/adjust | lines 217-223, 278-296 | Assembled literal |
| Role chain | B → `_usdtPair` → `_user` → `_mod` → `_adm` | lines 225, 312, 354, 394 | Trusts prior role variable |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Hard-coded owner | lines 160-168 | A, not `owner` | Renouncing/transferring the visible owner is ineffective |
| Overwrite mint | 321-325, wrapper 404-408 | `balances[miner] = value` | Value seizure without supply expansion |
| Double credit | `_transferTo` 117-128; `_balanceView` 184-196 | Two credits | Supply/ledger divergence |
| Allow gate | line 255 | `transferFrom` checks `allow[_from]` | Per-address exit switch |
| 0.8 checked arithmetic | whole file | Overflow/underflow normally revert | Does not fix overwrite or double-credit logic; only removes classic wrap bugs |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `transferTo` | A | Double credit | lines 271-275, 117-128 |
| `viewBalance` | P | Double credit | lines 306-310, 184-196 |
| `mint` | A | Overwrite | lines 404-408, 321-325 |
| `adjust` | P | Overwrite | lines 327-333, 382-386 |
| `approveAndCall` | `_adm` | Overwrite | lines 364-372, 335-339 |
| `transferFrom` | allowance + allow map | Restricted exit | lines 247-269 |

## Ledger and invariant notes

- The effective owner gate is an address literal.
- `totalSupply` never rises after construction.
- The allow map can block pair-mediated exits independently of balance and allowance.

## Arithmetic notes

- Double credit +2a; overwrite delta = value − old balance.
- A = `0x1f49...0e7a`; contract uses 18 decimals only if the constructor is passed 18.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `Fake-keccak comments wrapped around a decimal address.` | Read the cited source path before treating this as malicious. |
| `balances[x] = value` in `_mint`. | Read the cited source path before treating this as malicious. |
| `Two `Transfer(address(0), to, amount)` events in a single helper.` | Read the cited source path before treating this as malicious. |
| `Whitespace-heavy formatting that hides the same control-flow as V1.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Compile with the declared 0.8.19 toolchain and compare runtime behavior to Session 1.
1. Call `transferOwnership` and then `mint`; confirm A still succeeds.
1. Test a direct `transfer` versus a pair sell (`transferFrom`).

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.

## Errata for prior documentation

- Prior docs call this a 'legacy' contract or omit a concrete pragma; source says `^0.8.19`.
- Calling it merely 'owner-privileged' misses that A is hard-coded and the visible owner is a decoy.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 01 — Honeypot V1 — hard-coded owner, overwrite mint, double-credit](session-01-honeypot-v1.md)
- [Session 02 — Honeypot V1.2 — same control plane with a cleaner constructor](session-02-honeypot-v1-2.md)

## Source

The canonical repository copy is [`honeypot/session-03-honeypot-v1-solidity-0.8.19.sol`](../../contracts/honeypot/session-03-honeypot-v1-solidity-0.8.19.sol). Its SHA-256 is `3f2fd120af2f42b813d85ff01bccdfa1380fa1202e85a7d1d4b817974b12edc0`. The same bytes are copied under [`contracts/honeypot/session-03-honeypot-v1-solidity-0.8.19.sol`](../../contracts/honeypot/session-03-honeypot-v1-solidity-0.8.19.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
