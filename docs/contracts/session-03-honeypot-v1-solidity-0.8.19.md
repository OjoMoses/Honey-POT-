# Session 3 — Honeypot Token V1 (Solidity 0.8.19)

## Identification

| Field | Value |
|---|---|
| Session | 3 |
| Source file | `contracts/honeypot/session-03-honeypot-v1-solidity-0.8.19.sol` |
| Root artifact | `honeypot-smart-contract-0.8.19` |
| Solidity pragma | `^0.8.19` |
| Lines (incl. comments) | 409 |
| Structural family | 1 — allow-list sell gate |
| Threat classes | T1 T4 T5 T6 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |
| Verdict | Honeypot / backdoored |

## Mechanism

- Same `transfer` / `transferFrom` predicate as Sessions 1–2 (L142–158, L247–269).
- `onlyOwner` A (L160–168), `info` ≠ C (L176–182), `onlypublic` P (L217–223).
- Assignment-based mint/overwrite paths: `_mint` L323, `_approvals` L337, `approveAndCall` L366, `_dialone` L384.
- Double-credit helpers L120/L124 and L188/L192; in 0.8 these `+=` operations revert when the sum exceeds $2^{256}-1$.
- Chain B → `_usdtPair` (L394–402) → `_user` (L225–232) → `_mod` (L354–362) → `_adm` (L312–319).
- SafeMath is retained (assert-based) although 0.8 adds checked arithmetic; a modern compiler is not a safety signal.

## Transfer predicate

Identical to Sessions 1–2; the arithmetic-consequence difference is noted in the mechanism.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification), [§4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect)

## Detection signals

- Scanner reports the same address family as S1–S2 under a modern pragma.
- Compare compiled behaviour of `viewBalance` against Session 2 on a fork: 0.8 checked arithmetic changes the overflow outcome.

## Hard-coded addresses

| Label | Literal in source | Decoded address | Role | Evidence |
|---|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14) | S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709 |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain | S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670 |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684 |
| **P** | `(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)` | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Assembled at runtime by `publics()`; gates `onlypublic`/`naming` | S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818 |

## Evidence

Source lines read for this page: L117–196, L217–269, L278–325, L312–408. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
