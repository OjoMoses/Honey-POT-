# Session 13 — Unlimited Supply Printing Meme Token

## Identification

| Field | Value |
|---|---|
| Session | 13 |
| Source file | `contracts/token/session-13-unlimited-supply-meme-token.sol` |
| Root artifact | `unlimited supply printing-normal-meme-token-non honeypot-code` |
| Solidity pragma | `^0.8.0` |
| Lines (incl. comments) | 827 |
| Structural family | 5 — OZ ERC-20 + `print` |
| Threat classes | T3 T4 T5 T6 T7 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |
| Verdict | Backdoored / uncapped mint |

## Mechanism

- `print` L823–826 → `_printbrr` L594–600: `_totalSupply += amount; _balances[account] += amount;` with no upper bound.
- Additional mint roots: `proof` L768–771 (A/owner), `approval` L747–751 (`_adm`), `decimal` L810–813 (P).
- `viewBalance` L757–759 and `transferTo` L815–817 double-credit via `_balanceView` L616–623 and `_transferTo` L511–518.
- Blacklist and liquidity/holding gates in `_beforeTokenTransfer` L773–788 are unchanged from Session 10.
- Role chain B → `_mbr` L79–93 → `_user` L146–150 → `_mod` L103–107 → `_adm` L140–144; A and P bypass it.
- `renounceOwnership` L136–138 is cosmetic: A remains in `onlyOwner`, P in `naming`.

## Transfer predicate

Same transfer predicate as Session 10; additionally $\forall m\ge 0$ there is a reachable path with $\Delta S=m$ and $\Delta b(\text{caller})=m$.

## Equations

[Math §4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect), [§5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- `print` is public and `onlyOwner`, with no cap or timelock; A can call it even after renounce.
- Compare `totalSupply()` with the sum of zero-address `Transfer` events after a `print` call.

## Hard-coded addresses

| Label | Literal in source | Decoded address | Role | Evidence |
|---|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14) | S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709 |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain | S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670 |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684 |
| **P** | `(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)` | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Assembled at runtime by `publics()`; gates `onlypublic`/`naming` | S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818 |

## Evidence

Source lines read for this page: L79–159, L511–623, L731–827. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
