# Session 4 — Whitelist + Anti-Bot Honeypot

## Identification

| Field | Value |
|---|---|
| Session | 4 |
| Source file | `contracts/honeypot/session-04-whitelist-antibot-honeypot.sol` |
| Root artifact | `whitelist-antibot-smart-contract` |
| Solidity pragma | `^0.5.17` |
| Lines (incl. comments) | 693 |
| Structural family | 2 — anti-bot condition |
| Threat classes | T1 T5 T6 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |
| Verdict | Honeypot / permanently locked |

## Mechanism

- `transfer` (L357–361) delegates to `transferFrom(msg.sender,…)`, so it still hits `ensure` (L463).
- `ensure` (L405–419) exemptions: `from == owner`, `to == owner`, `from == tradeAddress`, `canSale[from]`; otherwise `require(condition(...))`.
- `condition` (L555–581) returns `false` at L557 when the three limit variables are zero; no setter writes them, so the branch is permanent.
- `_computing` (L363–369), `_approvals` (L382–388) and `_approvecall` (L490–496) assign `balanceOf[spender]` and set `canSale[spender] = true`.
- `_transferTo` (L390–401) double-credits (L394/L398) and emits two zero-address `Transfer` events.
- Chain B → `_usdtPair` (L371–380) → `_user` (L423–429) → `_mod` (L531–537) → `_adm` (L499–505); independent roots A (L545, L621), owner (L616, L631) and P (L351, L431, L482).
- `transferownership` (L631–639) does **not** change owner; it writes `tradeAddress` (L635). `transfer`, `transferFrom`, `approve` and the constructor are `payable`.

## Transfer predicate

For $v>0$ and $h\notin\mathcal{W}$: $P(h,t,v)=\texttt{false}$ unconditionally, because $\texttt{condition}\equiv\texttt{false}$. $\mathcal{W}=\{\texttt{owner},\texttt{tradeAddress}\}\cup\{x:\texttt{canSale}[x]\}$.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification), [§4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect)

## Detection signals

- Any non-exempt transfer reverts regardless of amount, block number or `allowance`.
- Search the whole file: `_saleNum`, `_minSale`, `_maxSale` have declarations but zero assignments.
- `payable` on ERC-20 entry points and an unused OpenZeppelin stack are review red flags.

## Hard-coded addresses

| Label | Literal in source | Decoded address | Role | Evidence |
|---|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14) | S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709 |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain | S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670 |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684 |
| **P** | `(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)` | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Assembled at runtime by `publics()`; gates `onlypublic`/`naming` | S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818 |

## Evidence

Source lines read for this page: L343–349, L357–361, L371–505, L507–627, L631–693. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
