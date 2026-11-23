# Session 1 — Honeypot Token V1

## Identification

| Field | Value |
|---|---|
| Session | 1 |
| Source file | `contracts/honeypot/session-01-honeypot-v1.sol` |
| Root artifact | `honeypot-smart-contract` |
| Solidity pragma | `^0.4.26` |
| Lines (incl. comments) | 284 |
| Structural family | 1 — allow-list sell gate |
| Threat classes | T1 T4 T5 T6 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |
| Verdict | Honeypot / backdoored |

## Mechanism

- `onlyOwner` (L17–24) requires `msg.sender == A` and never reads the stored `owner`; `owner` is decorative (L13, L29).
- `transfer` (L130–140) checks only zero-address and balance; `transferFrom` (L168–184) adds allowance and `allow[_from]` (L176).
- `mint` (L281–283, `onlyOwner`) calls `_mint`, which **assigns** `balances[miner] = _value` (L219). `approveAndCall` (L243–252, `_adm`) and `adjust` (L222–225, **P**) also assign balances (L249, L265).
- `_transferTo` (L101–108) and `_balanceView` (L117–124) each credit the target twice and emit two `Transfer(0, …)` events without raising `totalSupply`.
- Four-step dormant chain: B → `_usdtPair` (L268–274) → `_user` (L153–156) → `_mod` (L238–241) → `_adm` (L213–216). All role slots default to zero.
- Negative guards: `info` excludes C (L112–115); `contracts()` returns C (L203–207). `publics()` assembles P (L190–201).

## Transfer predicate

$P_{\texttt{transfer}}(h,t,v)=[t\ne 0]\land[v\le b(h)]$; $P_{\texttt{transferFrom}}(h,t,v)=P_{\texttt{transfer}}\land[v\le allowed[h][\text{caller}]]\land\texttt{allow}[h]$.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification), [§4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect), [§5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- Fresh-address router sell reverts while a wallet-to-wallet `transfer` succeeds.
- Scanner: 3 unique decimal addresses (6 occurrences), fragment assembly, hard-coded address in `onlyOwner`, 2 double-credit helpers, 3 role edges.
- Two `Transfer(address(0),…)` events per helper call; sum of balances exceeds `totalSupply()`.

## Hard-coded addresses

| Label | Literal in source | Decoded address | Role | Evidence |
|---|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14) | S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709 |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain | S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670 |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684 |
| **P** | `(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)` | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Assembled at runtime by `publics()`; gates `onlypublic`/`naming` | S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818 |

## Evidence

Source lines read for this page: L17–24, L101–124, L130–140, L153–156, L168–184, L190–207, L213–283. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
