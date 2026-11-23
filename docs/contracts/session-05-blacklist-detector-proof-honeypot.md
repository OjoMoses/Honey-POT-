# Session 5 — Blacklist + Detector-Proof Honeypot

## Identification

| Field | Value |
|---|---|
| Session | 5 |
| Source file | `contracts/honeypot/session-05-blacklist-detector-proof-honeypot.sol` |
| Root artifact | `honeypot-scanner-detector-proof-token` |
| Solidity pragma | `0.5.16` |
| Lines (incl. comments) | 741 |
| Structural family | 3 — blacklist, BEP-20 |
| Threat classes | T3 T4 T5 T6 T7 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |
| Verdict | Honeypot / selective freeze |

## Mechanism

- `onlyOwner` (L314–322) accepts A or stored owner (unless it is C); `Exchanges` excludes C (L383–386); `onlypublic` accepts P (L394–397).
- `_transfer` (L636–644) checks `!isBlacklisted[sender]`, zero addresses and balance; 1:1 credit, no fee. `transfer` and `transferFrom` share this path.
- Uncapped mint: `_calculate` (L476–482) via `symbols` (L544–547, `onlypublic`); `_proof` (L655–661) via `approval` (L562–566, `_adm`) and `proof` (L682–685, `onlyOwner`).
- `_transferTo` (L438–445) and `_balanceView` (L462–469) double-credit. `_burn`/`_burnFrom` are internal-only.
- Chain B → `_mbr` (L410–416) → `_user` (L450–453) → `_mod` (L471–474) → `_adm` (L498–501), all zero at deployment; P is an independent role.
- `renounceOwnership` (L331–334) zeroes the stored owner but A still passes `onlyOwner`. Comment at L328–329 claims the opposite.

## Transfer predicate

$P(h)=[\neg\texttt{isBlacklisted}[h]]\land[h\ne 0]\land[t\ne 0]\land[v\le b(h)]$; `isBlacklisted` is writable by A or the stored owner at any time.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification), [§5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- A fresh address sells successfully; the same address fails after a privileged `zap` transaction.
- Error string says `Recipient` while the require checks `sender`.
- No D in this file: D appears from Session 6 onward.

## Hard-coded addresses

| Label | Literal in source | Decoded address | Role | Evidence |
|---|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14) | S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709 |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain | S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670 |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684 |
| **P** | `(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)` | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Assembled at runtime by `publics()`; gates `onlypublic`/`naming` | S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818 |

## Evidence

Source lines read for this page: L288–322, L331–397, L410–501, L511–661, L674–729. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
