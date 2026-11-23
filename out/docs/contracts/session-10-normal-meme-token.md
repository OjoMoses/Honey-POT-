# Session 10 — Meme Token labelled “Normal” (not clean)

| Field | Value |
|---|---|
| Category | token |
| Source file | `contracts/token/session-10-normal-meme-token.sol` |
| Original root file | `normal-meme-pepe-token-non honeypot-code` |
| Solidity | `^0.8.0` |
| Length | 822 lines |
| Structural family | 5 (OZ ERC-20 + trade limits) |
| Threat classes | T3 T4 T5 T6 T7 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

OpenZeppelin-style ERC-20 with owner blacklist and holding limits on pair buys. **Despite the “non-honeypot” label it carries the hidden control plane**: `Ownable.onlyOwner` accepts **A**, and several mint paths exist.

## How it works

- `_beforeTokenTransfer`: reverts for blacklisted parties; while `LiquiduniswapV2Pair == 0`, only the owner may transact; with `tradelimited`, buys must keep the recipient between `minHoldingAmount` and `maxHoldingAmount`.
- `blacklist(addr,bool)` is `onlyOwner`; owner-or-**A**.
- Mint paths: `proof` (onlyOwner), `approval(uint256)` (`_adm`), `decimal(uint256)` (`naming` = **P**). `viewBalance` double-credits.
- `reviewRules` (**P**) overwrites pair and limits; role chain starts at **B**.
- `renounceOwnership()` exists but does not remove **A**'s access.

## Transfer predicate

$P(h)=\lnot\texttt{blacklists}[h]\land\text{limits}$; blacklist writable by owner or **A**.

## Equations

[Math §4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect), [§5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)

## Detection signals

- Scanner: 3 decimal literals, assembled address, hard-coded address in `onlyOwner`.
- Function names (`decimal`, `approval`) that mint.

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
