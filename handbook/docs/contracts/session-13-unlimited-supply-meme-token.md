# Session 13 — Unlimited-supply meme token — Session 10 plus owner `print` mint

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control  
> **Verdict:** `malicious`  
> **Confidence:** High for source-level control; deployment not tested  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`token/session-13-unlimited-supply-meme-token.sol`](../../contracts/token/session-13-unlimited-supply-meme-token.sol) |
| Pragma | `^0.8.0` |
| Lines | 827 |
| SHA-256 | `57caed22640a34bc752bbb0397d106ae572f0bd82005682a41961fd52b5a0122` |
| Family | Malicious hidden control |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

Session 10 with an additional owner-only `print` function that calls `_printbrr`. The rest of the hidden control plane is unchanged: A-or-owner gate, B-started role chain, P-controlled rules and `decimal`, `_adm` `approval`, and double-credit transfer helpers. The filename's 'unlimited supply' is accurate.

## What a user experiences

The token can be paused for non-owners by leaving the pair unset, can be blacklisted, and can be diluted or double-credited by privileged actors. The owner can print new supply directly, in addition to the other mint routes.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | Hard-coded owner; `proof`, `print`, blacklist, rules, transferTo | 116-127; `print` 823-826 | Direct |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts role chain | 79-93, 146, 103, 140 | Direct |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `naming`: viewBalance, decimal, reviewRules | 797-808, 738-741 | Assembled literal |
| `_adm` | `approval` mint | 747-751 | Role chain |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Owner print | 823-826 | `_printbrr` mints supply + balance | Direct inflation |
| All Session 10 controls | 116-127, 79-751, 773-817 | Hard-coded owner, role chain, blacklist, pair gate, double credit | Inherited trap |
| P rules | 790-795 | P changes pair/limits | Second operator can freeze trading |
| Double credit | 511-518, 616-623 | +2a, supply +0 | Ledger divergence |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `print(amount)` | A or owner | Mint to caller | 823-826, 594-600 |
| `proof` / `approval` / `decimal` | A-or-owner / `_adm` / P | Mint | 768-771, 747-751, 810-813 |
| `transferTo` / `viewBalance` | A-or-owner / P | Double credit | 815-817, 757-759 |
| `reviewRules` | P | Change pair/limits | 790-795 |
| `_beforeTokenTransfer` | blacklist / pair / limits | Transfer gate | 773-788 |

## Ledger and invariant notes

- Supply is unbounded through `print`, `proof`, `approval`, and `decimal`.
- A remains owner after renounce.
- P can change trading rules without owner.
- `transferTo`/`viewBalance` break the balance-sum invariant.

## Arithmetic notes

- `print(1e18)` adds 1e18 supply and balance.
- Holder 100k/1m diluted to 5% by +1m print.
- Double credit +2a; supply +0.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `print` calls `_printbrr`; `_printbrr` duplicates `_proof` mint logic. | Read the cited source path before treating this as malicious. |
| `All Session 10 hidden-control signatures.` | Read the cited source path before treating this as malicious. |
| `P-only `reviewRules` and `decimal`.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Call `print` from A and compare supply/balance.
1. Renounce, then call `print` from A.
1. Attempt non-owner transfer with pair unset.
1. Use P to set max holding to zero and buy.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- No deployment was inspected for actual pair configuration.

## Errata for prior documentation

- Prior docs classify this as 'unlimited supply' but do not connect `print` to the full Session 10 control plane.
- The `print` function is owner-gated, not public.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 10 — “Normal” meme token — full hidden control plane under an OZ-looking shell](session-10-normal-meme-token.md)
- [Session 14 — V2 unlimited-supply meme token — UUPS, public initialize, double supply](session-14-v2-unlimited-supply-meme-token.md)

## Source

The canonical repository copy is [`token/session-13-unlimited-supply-meme-token.sol`](../../contracts/token/session-13-unlimited-supply-meme-token.sol). Its SHA-256 is `57caed22640a34bc752bbb0397d106ae572f0bd82005682a41961fd52b5a0122`. The same bytes are copied under [`contracts/token/session-13-unlimited-supply-meme-token.sol`](../../contracts/token/session-13-unlimited-supply-meme-token.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
