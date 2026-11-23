# Session 2 — Honeypot Token V1.2

## Identification

| Field | Value |
|---|---|
| Session | 2 |
| Source file | `contracts/honeypot/session-02-honeypot-v1-2.sol` |
| Root artifact | `honeypot-contract-V1.2` |
| Solidity pragma | `^0.4.26` |
| Lines (incl. comments) | 265 |
| Structural family | 1 — allow-list sell gate |
| Threat classes | T1 T4 T5 T6 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |
| Verdict | Honeypot / backdoored |

## Mechanism

- `transfer` (L93–101) unrestricted; `transferFrom` (L163–174) requires `allow[_from]` (L167).
- `onlyOwner` accepts A (L103–110); `info` excludes C (L116–120); `onlypublic` accepts P (L143–147).
- `mint` (L262–264) → `_mint` assignment (L210); `approveAndCall` (L236–240, `_adm`) → `_approvals` assignment (L219) **with** `info`; `adjust` (L213–216) → `_dialone` (L251).
- `_transferTo` (L76–83) and `_balanceView` (L122–129) double-credit (L78/L81 and L124/L127).
- Chain B → `_usdtPair` (L254–260) → `_user` (L149–152) → `_mod` (L229–232) → `_adm` (L204–207). Role slots start zero.
- Pure `showuint160` (L72–74) is a conversion helper, not a safety feature.

## Transfer predicate

Same as Session 1; `P` for `transferFrom` additionally includes `allow[_from]`.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification), [§4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect)

## Detection signals

- Diff against Session 1 shows only restructuring, `showuint160`, the extra `info` guard on `_approvals`, and an unused `sellOutNum`.
- Router sell from a fresh address reverts; direct `transfer` works.

## Hard-coded addresses

| Label | Literal in source | Decoded address | Role | Evidence |
|---|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14) | S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709 |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain | S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670 |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684 |
| **P** | `(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)` | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Assembled at runtime by `publics()`; gates `onlypublic`/`naming` | S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818 |

## Evidence

Source lines read for this page: L72–74, L76–129, L93–120, L143–174, L204–264. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
