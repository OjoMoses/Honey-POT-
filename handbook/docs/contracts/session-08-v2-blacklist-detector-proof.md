# Session 08 — V2 blacklist honeypot — UUPS proxy, public initialize, D-gated mint

[Back to the contract index](index.md) · [Handbook home](../../README.md)

> **Classification:** Malicious hidden control (upgradeable)  
> **Verdict:** `malicious`  
> **Confidence:** High for source-level control; proxy deployment not tested  
> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.

## At a glance

| Field | Value |
|---|---|
| Source | [`honeypot/session-08-v2-blacklist-detector-proof.sol`](../../contracts/honeypot/session-08-v2-blacklist-detector-proof.sol) |
| Pragma | `^0.8.24` |
| Lines | 741 |
| SHA-256 | `13ab33b605c4b0e023ba07334f1b2ea6abe9fb27175daacee2e2a8d0144a285a` |
| Family | Malicious hidden control (upgradeable) |
| Page generator | `tools/gen_session_pages.py` from `tools/contract_facts.py` |

A UUPS port of the blacklist family. `initialize` is public and the implementation does not call `_disableInitializers`; ownership is A-or-stored-owner, and A survives renounce. The blacklist checks only the sender. A new D-gated `setMedium` path feeds `scaling`, which mints to the caller. P can mint through `adjust`, and `_adm` through `approval`.

## What a user experiences

A proxy can be initialized by whoever calls first if deployment is not atomic. The owner/A can blacklist sellers and mint; P and `_adm` have additional mint routes. A blacklisted address can still receive. The upgrade key is the same onlyOwner gate, so A can replace the implementation.

## Control plane

The table records who can do what, where the gate is, and how the actor is reached. A hard-coded address is not automatically the deployer; verify the key's ownership outside this repository before drawing a real-world attribution.

| Actor | Authority | Source evidence | Reachability |
|---|---|---|---|
| A = 0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a | `onlyOwner`, including `_authorizeUpgrade`; mint/blacklist/transferTo | modifier 358-367; literal 361; upgrade 486 | Direct; can upgrade the proxy |
| Original `_owner` | Second branch of `onlyOwner`, excluding C | line 364 | Initialize caller until renounce |
| D = 0x63e67a280645edf97880c1df03c8301b151c4668 | `setMedium`; then `scaling` mints for `_miu` | 517-524, 418-422, 533-539 | Direct; D can set itself as `_miu` |
| B = 0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051 | Starts role chain | 442-449; chain 462, 472, 493 | Direct |
| P = 0x7addad09cbd98d97ec3da7a0088eadfe5801c336 | `onlypublic`: `viewBalance` double credit, `adjust` mint | 381-392, 513-515, 478-481 | Assembled literal |
| `_adm` | `approval` mint | 562-566 | Role chain |

## Primitives that create the trap

| Primitive | Location | Effect | Why it matters |
|---|---|---|---|
| Public initialize | 306-320 | First caller becomes `_owner` and receives supply; no `_disableInitializers` | Deployment race / implementation initialization |
| Hard-coded owner + renounce | 358-367, 376-379 | A survives renounce | False renounce |
| Upgradeable | 486 | `_authorizeUpgrade` is onlyOwner | A can change code, not just parameters |
| D-gated mint | 517-524, 418-422, 533-539 | D sets `_miu`; `_miu` mints via `scaling` | Fourth mint authority beyond owner/P/_adm |
| Sender-only blacklist | 636-644 | Recipient not checked | Incomplete freeze semantics |
| Double credit | 394-401, 424-431 | +2a, supply +0 | Ledger inflation |

## Privileged and accounting paths

Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).

| Function / path | Gate | Effect | Evidence |
|---|---|---|---|
| `initialize` | public, `!initialized` | Sets owner, supply, balance; no disable | 306-320 |
| `setMedium` → `scaling` | D then `_miu` | Mint to `_miu` | 517-524, 418-422, 533-539 |
| `proof` | A or `_owner` | Mint to caller | 682-685, 655-661 |
| `adjust` | P | Mint to caller | 478-481, 554-560 |
| `approval` | `_adm` | Mint to `_adm` | 562-566 |
| `transferTo` / `viewBalance` | A-or-owner / P | Double credit | 433-435, 513-515, 394-401, 424-431 |
| `zap` / `dezap` | A or `_owner` | Sender blacklist | 708-718 |

## Ledger and invariant notes

- `initialized` is a custom bool; the implementation can be initialized once.
- A remains an owner and upgrade authority after renounce.
- The blacklist does not block receiving.
- `scaling` is gated by `_miu`, but D controls `_miu`.

## Arithmetic notes

- `initialize(T)` sets supply T and balance T; no double mint in this version.
- `scaling(1000)` adds 1000 to supply and caller balance.
- Double credit +2a; supply +0.

These are source-level examples. See [`math.md`](../reference/math.md) and the reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) for exact integer checks.

## Detection signals

| Signal | Interpretation |
|---|---|
| `UUPS import plus a public `initialize` with no `_disableInitializers` call.` | Read the cited source path before treating this as malicious. |
| `_authorizeUpgrade` behind an onlyOwner gate that includes a literal. | Read the cited source path before treating this as malicious. |
| `setMedium` literal gate leading to `scaling`. | Read the cited source path before treating this as malicious. |
| `onlyOwner` is `(literal \|\| _owner && msg.sender != exchange())`. | Read the cited source path before treating this as malicious. |
| `Sender-only blacklist require.` | Read the cited source path before treating this as malicious. |

## Verification plan (not run)

The following tests are proposed. They are not evidence that the behavior was observed on-chain.

1. Deploy implementation and proxy on a fork; attempt to initialize the implementation from a non-deployer.
1. Race a second initialize on a freshly deployed proxy; record whether the first caller wins.
1. Call `setMedium(D)` as D, then `scaling` as D; verify mint.
1. Renounce as `_owner`, then call `proof` from A.

## Limits and open questions

- No compiler, bytecode, fork, or live deployment was available. All reachability statements are source-level and conditional on deployment storage, proxy wiring, and the caller actually holding the named privilege.
- Upgradeability and initializer race findings are source-level; actual proxy admin/storage layout was not exercised.

## Errata for prior documentation

- Prior docs call this 'V2 blacklist detector-proof' without noting UUPS upgrade authority or public initialize.
- The blacklist is not bidirectional.
- The D/`_miu` mint chain is not mentioned in prior docs.

See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.

## Related sessions

- [Session 05 — Blacklist + detector-proof honeypot — hard-coded owner and mint paths](session-05-blacklist-detector-proof-honeypot.md)
- [Session 09 — V2 whitelist-switchable — UUPS fee token with hidden minters](session-09-v2-whitelist-switchable.md)
- [Session 14 — V2 unlimited-supply meme token — UUPS, public initialize, double supply](session-14-v2-unlimited-supply-meme-token.md)

## Source

The canonical repository copy is [`honeypot/session-08-v2-blacklist-detector-proof.sol`](../../contracts/honeypot/session-08-v2-blacklist-detector-proof.sol). Its SHA-256 is `13ab33b605c4b0e023ba07334f1b2ea6abe9fb27175daacee2e2a8d0144a285a`. The same bytes are copied under [`contracts/honeypot/session-08-v2-blacklist-detector-proof.sol`](../../contracts/honeypot/session-08-v2-blacklist-detector-proof.sol) in this handbook.

---

Generated from the fact table. Do not edit this page by hand; edit `tools/contract_facts.py` and rerun the generator.
