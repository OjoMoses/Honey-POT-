# Session 9 — Upgraded V2 Whitelist + Switchable Honeypot

## Identification

| Field | Value |
|---|---|
| Session | 9 |
| Source file | `contracts/honeypot/session-09-v2-whitelist-switchable.sol` |
| Root artifact | `Session 2 - Upgraded V2 Whitelist Switch On-Off Honeypot Mode.sol` |
| Solidity pragma | `^0.8.0` |
| Lines (incl. comments) | 401 |
| Structural family | 4 — fee switch, UUPS |
| Threat classes | T2 T4 T5 T6 T7 T8 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |
| Verdict | Honeypot / UUPS + 100% fee |

## Mechanism

- `initialize` L66–78 sets `owner`, `feeManager`, full supply to caller; no `_disableInitializers`; `_authorizeUpgrade` L80 `onlyOwner` (accepts A).
- `transfer` L86–95 fee-free; `transferFrom` L211–239 charges `sellFee` unless `isFeeExempt[_from]`; `sell()` L376–390 ignores the exemption.
- Fee setters with `<= 100` caps: `FeeStructure` L166–173, `BuySellFee` L269–275, `setScale` L293–299, `setFees` L320–326, `setting` L361–368.
- Mint paths `_scale` L98–104, `_proof` L131–137, `_initiate` L241–247; double-credit `_transferTo` L152–159 and `_balanceView` L187–194.
- Chain B → `_mbr` L106–113 → `_user` L281–285 → `_mod` L304–308 → `_adm` L370–374; A and D bypass it.
- `renounceOwnership` L287–290 cosmetic; `LockLPToken()` L301–302 empty.

## Transfer predicate

$\tau_s(h)=0$ if $\texttt{isFeeExempt}[h]$, else $\texttt{sellFee}/100\in[0,1]$; `sell()` always charges $\texttt{sellFee}/100$.

## Equations

[Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier), [§5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- UUPS initializer front-running check: identify the first caller of `initialize` on the target chain.
- Scanner: UUPS, public `initialize`, A/D/B/C/P, 10 fee-cap hits, 2 double-credit helpers.
- Router sell at `sellFee = 100` yields zero to the seller.

## Hard-coded addresses

| Label | Literal in source | Decoded address | Role | Evidence |
|---|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14) | S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709 |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain | S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670 |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684 |
| **D** | `570329899025738970963394674811034510039273195112` | `0x63e67a280645edf97880c1df03c8301b151c4668` | Extra caller in `onlyAuthorize` (S6–S9) and `setMedium` (S8) | S6 L193; S7 L200; S8 L521; S9 L204 |
| **P** | `(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)` | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Assembled at runtime by `publics()`; gates `onlypublic`/`naming` | S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818 |

## Evidence

Source lines read for this page: L35–78, L86–239, L254–368, L392–400. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
