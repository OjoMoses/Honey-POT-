# Session 7 — Whitelist + Switchable Honeypot Mode

## Identification

| Field | Value |
|---|---|
| Session | 7 |
| Source file | `contracts/honeypot/session-07-whitelist-switchable-honeypot.sol` |
| Root artifact | `whitelist-switch on&off honeypot mode-honeypot-scanner-detector-proof-token` |
| Solidity pragma | `^0.8.0` |
| Lines (incl. comments) | 393 |
| Structural family | 4 — fee switch + exemption |
| Threat classes | T2 T4 T5 T6 T7 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |
| Verdict | Honeypot / 100% fee, exempt insiders |

## Mechanism

- `transfer` (L75–84) fee-free; `transferFrom` (L207–235) charges `amount*sellFee/100` unless `isFeeExempt[_from]`.
- `sell()` (L368–382) charges `sellFee` without consulting `isFeeExempt`; `buy()` (L332–351) credits `feeManager`/contract without increasing supply.
- Five fee setters with `<= 100` caps: L157–164, L260–266, L284–290, L312–318, L353–360.
- Modifiers: `onlyAuthorize` D (L197–205), `onlyOwner`/`onlyAuthorized` A (L301–310, L384–392), `onlypublic` P (L250–253), `Exchanges` ≠ C (L105–108).
- Mint paths `_scale` L87–93, `_proof` L121–127, `_initiate` L237–243; double credit `_transferTo` L142–149 and `_balanceView` L177–184.
- Chain B → `_mbr` (L96–103) → `_user` (L268–272) → `_mod` (L295–299) → `_adm` (L362–366). `renounceOwnership` L278–281 is cosmetic; `LockLPToken()` L292–293 empty.

## Transfer predicate

$\tau_s(h)=0$ if $\texttt{isFeeExempt}[h]$, else $\texttt{sellFee}/100\in[0,1]$ on `transferFrom`; `sell()` always uses $\texttt{sellFee}/100$.

## Equations

[Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier), [§5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- Compare router round-trip from an exempt and a non-exempt address at the same block.
- Watch `AddressSetFeeExempt` events and `removeFeeExemptStatus` calls.
- Scanner reports D, A, P, B, C and 10 fee-cap hits.

## Hard-coded addresses

| Label | Literal in source | Decoded address | Role | Evidence |
|---|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14) | S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709 |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain | S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670 |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684 |
| **D** | `570329899025738970963394674811034510039273195112` | `0x63e67a280645edf97880c1df03c8301b151c4668` | Extra caller in `onlyAuthorize` (S6–S9) and `setMedium` (S8) | S6 L193; S7 L200; S8 L521; S9 L204 |
| **P** | `(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)` | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Assembled at runtime by `publics()`; gates `onlypublic`/`naming` | S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818 |

## Evidence

Source lines read for this page: L75–108, L116–235, L250–368, L384–393. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
