# Session 8 — Upgraded V2 Blacklist + Detector-Proof Honeypot

## Identification

| Field | Value |
|---|---|
| Session | 8 |
| Source file | `contracts/honeypot/session-08-v2-blacklist-detector-proof.sol` |
| Root artifact | `Session 1 - Upgraded V2 Blacklist Honeypot Detector Proof.sol` |
| Solidity pragma | `^0.8.24` |
| Lines (incl. comments) | 741 |
| Structural family | 3 — blacklist, UUPS |
| Threat classes | T3 T4 T5 T6 T7 T8 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |
| Verdict | Honeypot / UUPS + blacklist |

## Mechanism

- `initialize(name,symbol,supply,decimals)` L306–320; no constructor, no `_disableInitializers`; first caller wins.
- `transfer`/`transferFrom` both call `_transfer` (L508–511, L580–584); `_transfer` (L636–644) rejects blacklisted **sender** with `"Recipient is Gwei"`; no fee state.
- `zap`/`dezap` (L708–718) are `onlyOwner`; A can call them via the modifier.
- Uncapped mint: `_scale` L533–539 via `scaling` (L418–422, `_miu`); `_proof` L655–661 via `proof` (L682–685, A/owner) and `approval` (L562–566, `_adm`); `_dialone` L554–560 via `adjust` (L478–481, P).
- Double-credit: `_transferTo` L394–401 (L396/L399) and `_balanceView` L424–431 (L426/L429).
- Parallel role root: `setMedium` (L517–524) is hard-coded to D and writes `_miu`. Main chain B → `_mbr` L442–449 → `_user` L462–466 → `_mod` L472–476 → `_adm` L493–497.
- `renounceOwnership` L376–379 zeroes `_owner`; A still passes `onlyOwner` and can authorise upgrades.

## Transfer predicate

$P(h)=[\neg\texttt{isBlacklisted}[h]]\land[h\ne 0]\land[t\ne 0]\land[v\le b(h)]$; upgrade predicate is $\text{caller}=A\lor(\text{caller}=owner\land\text{caller}\ne C)$.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification), [§5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- Review the proxy admin and the first `initialize` transaction; compare implementation bytecode.
- Scanner: UUPS + public `initialize` + `renounceOwnership` + D-gated `setMedium` + A in `onlyOwner`.
- After renounce, impersonate A on a fork and confirm `onlyOwner` functions still succeed.

## Hard-coded addresses

| Label | Literal in source | Decoded address | Role | Evidence |
|---|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14) | S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709 |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain | S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670 |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684 |
| **D** | `570329899025738970963394674811034510039273195112` | `0x63e67a280645edf97880c1df03c8301b151c4668` | Extra caller in `onlyAuthorize` (S6–S9) and `setMedium` (S8) | S6 L193; S7 L200; S8 L521; S9 L204 |
| **P** | `(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)` | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Assembled at runtime by `publics()`; gates `onlypublic`/`naming` | S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818 |

## Evidence

Source lines read for this page: L282–320, L358–435, L442–524, L533–661, L674–729. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
