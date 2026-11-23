# Session 12 — Auto-renounce meme token — fixed supply, owner revoked in constructor

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** No hidden control found (clean in scope)  
> **Verdict:** `clean`  
> **Confidence:** High for the listed surface; no compiler/fork run  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`token/session-12-auto-ownership-renounce-meme-token.sol`](../../contracts/token/session-12-auto-ownership-renounce-meme-token.sol) |
| Pragma | `^0.8.0` |
| Lines | 90 |
| SHA-256 | `c5e24018b2e582faba386255c63c04000686fd90fb71a528a5e922a0e0d58a7e` |
| Family | No hidden control found (clean in scope) |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

A small fixed-supply token. The constructor assigns the entire supply, sets `owner`, emits events, then calls `renounceOwnership()`. After deployment the owner is zero and no privileged function remains. Transfers use checked 0.8 arithmetic around an `unchecked` block that is guarded by a prior balance check.

## What a user experiences

The deployer starts with all tokens, then immediately renounces. There is no mint, fee, blacklist, pause, proxy, or owner-only value path. Trading is ordinary ERC-20 transfer/approve/transferFrom.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| Deployer | Initial supply; owner is renounced in the constructor | constructor 24-30 | No residual privilege |
| Anyone | Standard transfer/approve/transferFrom | 36-84 | No allowlist |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Auto-renounce | constructor 24-30 | Sets owner to zero before deployment completes | No lingering owner |
| Fixed supply | line 8 | 1e24 base units | No mint function |
| Guarded unchecked transfer | 41-54 | Requires sender balance before unchecked subtraction | No underflow in this path |
| No hooks/proxy | whole file | No hidden callback or upgrade | Small attack surface |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `transfer` / `transferFrom` | balance + allowance | Standard movement | 36-84 |
| `approve` | caller | Standard allowance | 56-67 |
| `renounceOwnership` | owner, but owner is already zero | No further privilege | 86-89 |

## Ledger and invariant notes

- `owner == address(0)` after construction.
- `totalSupply` is a state variable set once and never modified.
- No external function changes `_balances` except transfer/transferFrom.

## Arithmetic notes

- Supply = 1,000,000 * 10^18 = 1e24 base units.
- Transfer of 1000 moves exactly 1000; no fee.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `No address literal, no role chain, no mint/fee/blacklist.` | Read the cited source path before treating this as malicious. |
| `Constructor calls `renounceOwnership`.` | Read the cited source path before treating this as malicious. |
| `Only owner-gated function is renounce itself.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Read `owner()` after deployment; expect zero.
1. Attempt to call every function as a non-owner; expect normal ERC-20 results.
1. Fuzz transferFrom allowance edge cases.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- This is a source-scope clean verdict; it is not an economic or deployment audit.
- A clean verdict here means no hidden-control primitive was found in this file. It is not a guarantee of economic safety, liquidity safety, or compiler/runtime equivalence.

## Errata for prior documentation

- Prior docs say the renounce claim 'requires verification'; the constructor and owner state verify it directly.
- The `unchecked` block is guarded by a prior `require`; do not report it as a standalone underflow bug.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 11 — Ownership-renounce meme token — conventional fixed-supply BEP-20](session-11-ownership-renounce-meme-token.md)
- [Session 15 — V2 auto-renounce meme token — constants, fixed supply, no proxy](session-15-v2-auto-ownership-renounce-meme-token.md)

## Source

The canonical repository copy is [`token/session-12-auto-ownership-renounce-meme-token.sol`](../../contracts/token/session-12-auto-ownership-renounce-meme-token.sol). Its SHA-256 is `c5e24018b2e582faba386255c63c04000686fd90fb71a528a5e922a0e0d58a7e`. The same bytes are copied under [`contracts/token/session-12-auto-ownership-renounce-meme-token.sol`](../../contracts/token/session-12-auto-ownership-renounce-meme-token.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
