# Session 6 — Switchable Honeypot Mode

## Identification

| Field | Value |
|---|---|
| Session | 6 |
| Source file | `contracts/honeypot/session-06-switchable-honeypot-mode.sol` |
| Root artifact | `switch on&off honeypot mode-honeypot-scanner-detector-proof-token` |
| Solidity pragma | `^0.8.0` |
| Lines (incl. comments) | 369 |
| Structural family | 4 — fee switch |
| Threat classes | T2 T4 T5 T6 T7 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |
| Verdict | Honeypot / 100% fee |

## Mechanism

- `transfer` (L73–82) moves the full amount; `transferFrom` (L200–224) debits the full amount, credits `amountAfterFee` to `_to` and the fee to the contract (L205–216).
- All five fee setters — `FeeStructure` L153–158, `BuySellFee` L249–255, `setScale` L273–279, `setFees` L300–306, `setting` L329–336 — require `new*Fee <= 100`; divisor is 100 (L205, L313, L347).
- Modifiers: `onlyAuthorize` accepts D (L190–198); `onlyOwner` and `onlyAuthorized` accept A (L290–298, L360–368); `onlypublic` accepts P (L239–242); `Exchanges` excludes C (L102–105).
- Uncapped mint via `_scale` L85–91 → `scaling` L167–170 / `FeesView` L234–237; `_proof` L118–124 → `rewire` L107–111 / `proof` L185–188; `_initiate` L226–232 → `compute` L113–116.
- `_transferTo` (L139–146) and `_balanceView` (L172–179) double-credit (2 × `+=`, 2 × events, no supply change).
- `buy()` (L308–327) credits tokens to `feeManager` for `msg.value` and keeps the ETH; `sell()` (L344–358) credits the contract and sends no ETH. `LockLPToken()` (L281–282) is empty.
- `renounceOwnership` (L267–270) zeroes `owner`; A, D, P and the role chain remain.

## Transfer predicate

$P_{\texttt{transfer}}\equiv\text{true}$ with $a_{\text{recv}}=a$; $P_{\texttt{transferFrom}}\equiv\text{true}$ with $a_{\text{recv}}=a(1-s)$ and $s=\texttt{sellFee}/100\in[0,1]$; $s=1\Rightarrow a_{\text{recv}}=0$.

## Equations

[Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier), [§4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect), [§5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- Wallet-to-wallet transfer shows 0 % fee; router sell shows `sellFee`.
- Scanner: 10 `<= 100` fee-cap hits, D in `onlyAuthorize`, A in two modifiers, P fragment, 2 double-credit helpers.
- Set `sellFee = 100` on a fork through each setter and confirm the seller receives zero tokens.

## Hard-coded addresses

| Label | Literal in source | Decoded address | Role | Evidence |
|---|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14) | S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709 |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain | S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670 |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684 |
| **D** | `570329899025738970963394674811034510039273195112` | `0x63e67a280645edf97880c1df03c8301b151c4668` | Extra caller in `onlyAuthorize` (S6–S9) and `setMedium` (S8) | S6 L193; S7 L200; S8 L521; S9 L204 |
| **P** | `(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)` | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Assembled at runtime by `publics()`; gates `onlypublic`/`naming` | S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818 |

## Evidence

Source lines read for this page: L37–58, L73–105, L113–198, L200–279, L290–368. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
