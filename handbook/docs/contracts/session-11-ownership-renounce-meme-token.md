# Session 11 — Ownership-renounce meme token — conventional fixed-supply BEP-20

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** No hidden control found (clean in scope)  
> **Verdict:** `clean`  
> **Confidence:** High for the listed surface; no compiler/fork run  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`token/session-11-ownership-renounce-meme-token.sol`](../../contracts/token/session-11-ownership-renounce-meme-token.sol) |
| Pragma | `0.5.16` |
| Lines | 588 |
| SHA-256 | `89c0524413007c54e2f6914b01162ba976003480f787867094f1f88d88123fa9` |
| Family | No hidden control found (clean in scope) |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

A conventional fixed-supply BEP-20 with standard transfer, approval, and allowance behavior. `renounceOwnership` revokes the only owner role, and no external function calls the internal `_mint`. The internal `_burn` and `_mint` exist but are not reachable from the public surface.

## What a user experiences

Transfers and approvals behave normally. The deployer owns the initial supply and can renounce ownership; after that there is no privileged mint, fee, blacklist, or transfer gate. There is no upgrade proxy.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| Deployer | Initial `_owner`; can renounce or transfer ownership | Ownable 280-337; constructor 351-359 | Only until renounce |
| Anyone | Standard transfer/approve/transferFrom | 411-518 | No allowlist |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Fixed supply | constructor 351-359 | 1,000,000 * 10^18 assigned once | No public mint |
| Internal-only mint | `_mint` 530-536 | No external caller | Not an inflation path in this file |
| Standard allowance | 447-451 | Subtracts allowance after transfer | No hidden exit gate |
| Renounce | 316-321 | Sets `_owner = 0`; no hard-coded fallback | Actually removes owner powers |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `transfer` / `transferFrom` | balance + allowance | Standard movement | 411-451 |
| `approve` / increase / decrease | caller | Standard allowance | 430-486 |
| `renounceOwnership` | owner | Revokes owner | 316-321 |

## Ledger and invariant notes

- `_totalSupply` is assigned only in the constructor; no external `_mint` call exists.
- No address literal or fragment assembly is present.
- No blacklist, fee, or transfer gate is present.
- After renounce, no function checks the old owner.

## Arithmetic notes

- Supply = 1,000,000 * 10^18 = 1,000,000,000,000,000,000,000,000 base units.
- No fee example applies; transfers move the exact amount.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `No `address(<decimal>)` or shifted-fragment address.` | Read the cited source path before treating this as malicious. |
| `No `onlyOwner` on a value-moving function other than renounce/transferOwnership.` | Read the cited source path before treating this as malicious. |
| `_mint` has no call site. | Read the cited source path before treating this as malicious. |
| `No UUPS import or initializer.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Call `renounceOwnership`; then call every external function and confirm none is owner-gated.
1. Search the AST/call graph for `_mint` callers; expect none.
1. Fuzz transfer/approve/transferFrom against a reference ERC-20.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- Standard ERC-20 approval-race and fee-on-transfer absence are noted, not treated as honeypot findings.
- A clean verdict here means no hidden-control primitive was found in this file. It is not a guarantee of economic safety, liquidity safety, or compiler/runtime equivalence.

## Errata for prior documentation

- Prior docs suggest renounce might be bypassable; source has no hard-coded fallback and no other owner-gated value path.
- The internal `_mint` is not an external mint; it has no call site in this file.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 12 — Auto-renounce meme token — fixed supply, owner revoked in constructor](session-12-auto-ownership-renounce-meme-token.md)
- [Session 15 — V2 auto-renounce meme token — constants, fixed supply, no proxy](session-15-v2-auto-ownership-renounce-meme-token.md)

## Source

The canonical repository copy is [`token/session-11-ownership-renounce-meme-token.sol`](../../contracts/token/session-11-ownership-renounce-meme-token.sol). Its SHA-256 is `89c0524413007c54e2f6914b01162ba976003480f787867094f1f88d88123fa9`. The same bytes are copied under [`contracts/token/session-11-ownership-renounce-meme-token.sol`](../../contracts/token/session-11-ownership-renounce-meme-token.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
