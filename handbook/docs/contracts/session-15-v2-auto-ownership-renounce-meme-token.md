# Session 15 — V2 auto-renounce meme token — constants, fixed supply, no proxy

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** No hidden control found (clean in scope)  
> **Verdict:** `clean`  
> **Confidence:** High for the listed surface; no compiler/fork run  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`token/session-15-v2-auto-ownership-renounce-meme-token.sol`](../../contracts/token/session-15-v2-auto-ownership-renounce-meme-token.sol) |
| Pragma | `^0.8.0` |
| Lines | 90 |
| SHA-256 | `51cd7d72381d026b515e6365b22d791f659b8afe8badb7600cac95ba8e029538` |
| Family | No hidden control found (clean in scope) |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

A constant-state variant of Session 12. `name`, `symbol`, `decimals`, and `totalSupply` are constants; the constructor assigns the supply and immediately renounces ownership. There is no mint, fee, blacklist, proxy, or owner-only value path. The 'V2' label does not imply upgradeability.

## What a user experiences

The deployer starts with all tokens and ownership is immediately burned. Transfers and approvals are standard. No operator can mint, freeze, tax, or upgrade the token through this source surface.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| Deployer | Initial supply; auto-renounces in constructor | 24-30 | No residual privilege |
| Anyone | Standard transfer/approve/transferFrom | 36-84 | No allowlist |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Constants | 5-8 | Compile-time metadata and supply | Cannot be changed at runtime |
| Auto-renounce | 24-30 | Owner zero after deployment | No lingering owner |
| Fixed supply | 8, 25 | 1e24 assigned once | No mint path |
| No proxy | whole file | No UUPS/initializer | No upgrade authority |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `transfer` / `transferFrom` | balance + allowance | Standard movement | 36-84 |
| `approve` | caller | Standard allowance | 56-67 |
| `renounceOwnership` | owner, already zero | No further privilege | 86-89 |

## Ledger and invariant notes

- `owner == address(0)` after construction.
- `totalSupply` is constant and never changes.
- No external function mint/burn/blacklist/fee.

## Arithmetic notes

- Supply = 1e24 base units.
- Transfer of 1000 moves exactly 1000; no fee.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `No address literal/fragment assembly, no UUPS import, no initializer.` | Read the cited source path before treating this as malicious. |
| `Constructor calls renounceOwnership.` | Read the cited source path before treating this as malicious. |
| `Only owner-gated function is renounce.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Read owner after deployment; expect zero.
1. Call renounce again; expect revert because owner is zero.
1. Fuzz standard transfer/allowance behavior.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- Source-scope clean verdict only; no economic or deployment audit.
- A clean verdict here means no hidden-control primitive was found in this file. It is not a guarantee of economic safety, liquidity safety, or compiler/runtime equivalence.

## Errata for prior documentation

- Prior docs call this 'V2' and imply a possible upgrade path; source has no proxy or initializer.
- Prior docs say the renounce claim needs verification; construction directly sets then clears owner.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 12 — Auto-renounce meme token — fixed supply, owner revoked in constructor](session-12-auto-ownership-renounce-meme-token.md)
- [Session 11 — Ownership-renounce meme token — conventional fixed-supply BEP-20](session-11-ownership-renounce-meme-token.md)

## Source

The canonical repository copy is [`token/session-15-v2-auto-ownership-renounce-meme-token.sol`](../../contracts/token/session-15-v2-auto-ownership-renounce-meme-token.sol). Its SHA-256 is `51cd7d72381d026b515e6365b22d791f659b8afe8badb7600cac95ba8e029538`. The same bytes are copied under [`contracts/token/session-15-v2-auto-ownership-renounce-meme-token.sol`](../../contracts/token/session-15-v2-auto-ownership-renounce-meme-token.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
