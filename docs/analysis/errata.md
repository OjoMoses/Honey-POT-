# Errata and Corrections to Earlier Documentation

The pre-existing handbook made claims that were not checked against each contract in full. This page lists what was wrong or misleading and where the corrected statement now lives. Contract facts were re-derived from the extracted `out/contracts/` tree and from the [indicator scanner](../../tools/scan_indicators.py); numeric corrections are reproduced by [`tools/verify_numbers.py`](../../tools/verify_numbers.py).

## Substantive corrections

| # | Earlier statement | Correction | See |
|---|---|---|---|
| E1 | S10, S13, S14 described as "normal" / "non honeypot" | All three contain the hidden control plane: hard-coded **A** in `onlyOwner`, a role chain, uncapped mint paths and double-credit helpers. S13 adds public `print(uint256)`. They are **not** safe examples. | [S10](../contracts/session-10-normal-meme-token.md), [S13](../contracts/session-13-unlimited-supply-meme-token.md), [S14](../contracts/session-14-v2-unlimited-supply-meme-token.md) |
| E2 | S11 grouped with the honeypot set; S12/S15 labelled "V2" as if upgraded | S11 is a plain BEP-20 with no hard-coded address, no reachable mint and a real renounce. S12/S15 are minimal fixed-supply tokens; S15 contains **no** proxy or initializer despite `V2`. | [S11](../contracts/session-11-ownership-renounce-meme-token.md), [S12](../contracts/session-12-auto-ownership-renounce-meme-token.md), [S15](../contracts/session-15-v2-auto-ownership-renounce-meme-token.md) |
| E3 | S4 described as having "no pragma" | `pragma solidity ^0.5.17;` at L1. The file also declares a decoy OpenZeppelin stack that `DevToken` does not inherit. | [S4](../contracts/session-04-whitelist-antibot-honeypot.md) |
| E4 | S2 "behaviour unchanged" from S1; S3 "behaviour unchanged" from S2 | **False strictly.** S2's `approveAndCall` routes through `_approvals`, adding the `info` (≠ C) guard absent in S1. S3 adds `return true;` to four role setters and 0.8 checked arithmetic changes overflow behaviour of the double-credit helpers. | [S2](../contracts/session-02-honeypot-v1-2.md), [S3](../contracts/session-03-honeypot-v1-solidity-0.8.19.md) |
| E5 | S14 reported supply treated as the ERC-20 supply | Public `totalSupply` (L620, set only in `initialize` L646) is **separate** from private `_totalSupply` (L209) increased by mint helpers. Reported supply does not reflect later mints. | [S14](../contracts/session-14-v2-unlimited-supply-meme-token.md) |
| E6 | S7 fee exemption assumed to apply to all sell paths | `transferFrom` skips the fee for `isFeeExempt[_from]` (L213–215), but `sell()` (L368–382) ignores the exemption entirely. Same defect in S9. | [Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier) |
| E7 | S1 `owner` treated as the privileged account | `onlyOwner` (L17–24) compares only to fixed **A**; the stored `owner` is written by `transferOwnership` (L26–30) and read nowhere. Same pattern across S1–S4. | [Control plane §1.3](control-plane.md#13-negative-guards-and-exclusion-lists) |
| E8 | D listed as present in S5 | S5 has only A, B, C and fragment-assembled P. **D first appears in S6** (`onlyAuthorize`, L193). | [IOC table](control-plane.md#2-ioc-address-table) |
| E9 | S8 described as a plain port of S5 | S8 adds a UUPS public `initialize` (first caller wins), `_authorizeUpgrade` gated by A-accepting `onlyOwner`, and a **D-gated** `setMedium` writing a second mint role `_miu` (L517–524). | [S8](../contracts/session-08-v2-blacklist-detector-proof.md) |
| E10 | 14 classic bait contracts presented as if verified here | Their sources are **not in the attached archive**. Entries are preserved as unverified pre-existing claims; only their arithmetic was re-checked independently. | [Classic catalog](../reference/classic-honeypots.md), [Math §6](../reference/math.md#6-classic-honeypot-arithmetic) |
| E11 | Round-trip retention described as $\gamma^2(1-i_b)(1-i_s)$ | Correct composition is $\rho=(1-i_b)(1-i_s)=\frac{99400900}{101991009}\approx0.974605$; multiplying by $\gamma^2$ double-counts fees and yields $\approx0.968766$. AMM price impact for the worked $10^6$-token sell is $\frac{1000}{1997}\approx0.5008$, not `0.9501`. | [Math §1](../reference/math.md#1-constant-product-amm) |
| E12 | Classic 10 shortfall stated as 1 wei; drain fractions stated with $\gamma$ omitted | Exact deposit sum is `99,999,999,999,999,979` wei, a **21 wei** shortfall from 100 finney. Drain fractions use integer-weighted $\gamma m$: `0.499249 / 0.908842 / 0.998998 / 0.999999`. | [Math §5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting), [§6.2](../reference/math.md#62-math-trick-10_math_tricksol) |
| E13 | `renounceOwnership()` in the UUPS sessions implied to remove upgrade power | In S8, S9 and S14 the same A-accepting modifier gates `_authorizeUpgrade`; A can still authorise an upgrade after renounce. | [S8](../contracts/session-08-v2-blacklist-detector-proof.md), [S9](../contracts/session-09-v2-whitelist-switchable.md), [S14](../contracts/session-14-v2-unlimited-supply-meme-token.md) |

## Duplicate copies and line endings

The attached zip was extracted cleanly to a clean temporary directory. Inventory and byte comparison scripts established:

* All 15 files under `out/contracts/` are byte-identical to the corresponding working-tree files under `contracts/` **after LF normalisation**. The working-tree copies use CRLF (e.g. 284 CRLF sequences in S1); the extracted copies use LF.
* After stripping comments and whitespace, all 15 pairs are **code-identical** (compact lengths equal). There is no hidden logic difference between the two trees.
* Root-level artifact files such as `honeypot-smart-contract`, `honeypot-contract-V1.2` and `normal-meme-pepe-token-non honeypot-code` are copies of the organised session files, not separate contracts.

Consequence: line numbers cited in this handbook refer to the extracted (LF) copies, and they map one-for-one onto the working-tree copies. Evidence reports: [`reports/inventory.txt`](../../reports/inventory.txt) and [`reports/duplicates.txt`](../../reports/duplicates.txt).

## Naming collisions

The root-level `Session 1…4 - Upgraded V2 …` files use a numbering that **does not match** the organised session numbers:

| Root file label | Actual session | Source file |
|---|---|---|
| `Session 1 - Upgraded V2 Blacklist Honeypot Detector Proof.sol` | **S8** | `contracts/honeypot/session-08-v2-blacklist-detector-proof.sol` |
| `Session 2 - Upgraded V2 Whitelist Switch On-Off Honeypot Mode.sol` | **S9** | `contracts/honeypot/session-09-v2-whitelist-switchable.sol` |
| `Session 3 - Upgraded V2 Automatic Ownership Renounce Meme Token.sol` | **S15** | `contracts/token/session-15-v2-auto-ownership-renounce-meme-token.sol` |
| `Session 4 - Upgraded V2 Unlimited Supply Printing Meme Token.sol` | **S14** | `contracts/token/session-14-v2-unlimited-supply-meme-token.sol` |

All session pages in this handbook use the organised S1–S15 numbering. Do not infer a contract's behaviour from either numbering label alone.

## Standing limitations

* No contract was compiled, deployed or executed. Behavioural claims are source-level plus exact arithmetic.
* Purpose of fixed address **C** is unknown from source.
* The 14 classic bait sources are absent; their behavioural descriptions remain unverified claims.
