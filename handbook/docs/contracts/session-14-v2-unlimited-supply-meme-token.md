# Session 14 — V2 unlimited-supply meme token — UUPS, public initialize, double supply

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control (upgradeable, defective initialization)  
> **Verdict:** `broken`  
> **Confidence:** High for source-level behavior; proxy not executed  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`token/session-14-v2-unlimited-supply-meme-token.sol`](../../contracts/token/session-14-v2-unlimited-supply-meme-token.sol) |
| Pragma | `^0.8.0` |
| Lines | 833 |
| SHA-256 | `f1618a898d4d5605846f52d69ca833293a3a9f78b731cc09d8615f1bbd899267` |
| Family | Malicious hidden control (upgradeable, defective initialization) |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

A UUPS port of Session 13. It retains the hard-coded A owner, role chain, blacklist, P rules, `proof`/`print`/`approval`/`decimal` mints, and double-credit helpers. It adds a public `initialize` with no `_disableInitializers` and sets `totalSupply` before calling `_mint`, which adds the supply a second time. The result is totalSupply = 2T with balance T on first initialization.

## What a user experiences

The first initializer can take ownership and supply if deployment is not atomic. The initialized ledger immediately reports twice the minted supply. After that, the same privileged mint/double-credit/rule controls as Session 13 remain, and A survives renounce.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| First initializer | Becomes `owner`; receives `_totalSupply` balance | 641-652 | Public, one-shot custom bool; no disable |
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | Hard-coded owner; `proof`, `print`, blacklist, rules, transferTo, upgrade | 703-714; upgrade 737 | Direct |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts role chain | 659-673, 743, 690, 727 | Direct |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `naming`: viewBalance, decimal, reviewRules | 807-818, 634-637 | Assembled literal |
| `_adm` | `approval` mint | 768-772 | Role chain |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Public initialize | 641-652 | No `_disableInitializers`; first caller owns and mints | Deployment race |
| Double supply on initialize | 646, 649, 457-467 | `totalSupply = T` then `_mint` adds T → 2T | Broken invariant from block one |
| UUPS upgrade | 737 | A or owner can replace implementation | A can change code |
| Owner print | 829-832 | Mint | Unbounded supply |
| Role/blacklist/rules | 659-790 | Session 13 control plane | Multiple hidden authorities |
| Double credit | 395-402, 500-507 | +2a, supply +0 | Ledger inflation |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `initialize` | public, `!initialized` | Double-counts supply; sets owner | 641-652, 457-467 |
| `print` / `proof` | A or owner | Mint | 829-832, 785-788 |
| `approval` / `decimal` | `_adm` / P | Mint | 768-772, 820-823 |
| `transferTo` / `viewBalance` | A-or-owner / P | Double credit | 733-735, 696-698 |
| `_authorizeUpgrade` | A or owner | Upgrade implementation | 737 |

## Ledger and invariant notes

- After initialize(T), `totalSupply == 2T` and `balanceOf(initializer) == T`.
- `initialized` is true after the first initialize, but the implementation has no disabled initializer state.
- A remains owner after renounce.
- Supply is unbounded via print/proof/approval/decimal.
- `owner` is private, but onlyOwner still includes A.

## Arithmetic notes

- T=1e24: initialize -> totalSupply=2e24, initializer balance=1e24.
- `print(1e18)` -> supply +1e18, balance +1e18.
- Double credit +2a; supply +0.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `UUPS import + public initialize + no `_disableInitializers`.` | Read the cited source path before treating this as malicious. |
| `initialize` assigns `totalSupply = _totalSupply` and then calls `_mint`. | Read the cited source path before treating this as malicious. |
| `Hard-coded A in `onlyOwner` and `_authorizeUpgrade`.` | Read the cited source path before treating this as malicious. |
| `P-only `reviewRules`/`decimal`, `_adm` `approval`, owner `print`/`proof`.` | Read the cited source path before treating this as malicious. |
| `Double `+=` helpers.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Initialize a fresh proxy with T; read totalSupply and balance; expect 2T/ T.
1. Attempt a second initialize; expect revert on the custom bool.
1. Deploy implementation and initialize it directly from a non-deployer.
1. Renounce, then print from A; then upgrade from A.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- The double-supply result is a source-level arithmetic conclusion; proxy storage/delegatecall was not executed.

## Errata for prior documentation

- Prior docs call this 'V2 unlimited supply' but miss that initialization itself doubles the reported supply.
- Prior docs do not mention public initialize, no initializer disable, or A's upgrade authority.
- The double credit is in the helpers, not the no-op tuple expression.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 13 — Unlimited-supply meme token — Session 10 plus owner `print` mint](session-13-unlimited-supply-meme-token.md)
- [Session 10 — “Normal” meme token — full hidden control plane under an OZ-looking shell](session-10-normal-meme-token.md)
- [Session 08 — V2 blacklist honeypot — UUPS proxy, public initialize, D-gated mint](session-08-v2-blacklist-detector-proof.md)

## Source

The canonical repository copy is [`token/session-14-v2-unlimited-supply-meme-token.sol`](../../contracts/token/session-14-v2-unlimited-supply-meme-token.sol). Its SHA-256 is `f1618a898d4d5605846f52d69ca833293a3a9f78b731cc09d8615f1bbd899267`. The same bytes are copied under [`contracts/token/session-14-v2-unlimited-supply-meme-token.sol`](../../contracts/token/session-14-v2-unlimited-supply-meme-token.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
