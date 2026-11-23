# Glossary and References

## Glossary

| Term | Meaning |
|---|---|
| **AMM** | Automated market maker; pool pricing by a formula ([Math §1](math.md#1-constant-product-amm)) |
| **Allow-list / whitelist** | Mapping of addresses exempt from a restriction ($\mathcal{W}$) |
| **Blacklist** | Mapping of addresses barred from transferring or receiving |
| **Bait contract** | Contract that appears to let a taker withdraw funds but is built so the taker loses |
| **Control plane** | The set of privileged functions and the paths that reach them ([analysis](../analysis/control-plane.md)) |
| **Cosmetic renounce** | `renounceOwnership()` present but another route to the same powers remains |
| **Double credit** | Adding the same amount to a balance twice without raising `totalSupply` ([Math §4](math.md#4-supply-invariants-and-the-double-credit-defect)) |
| **Fee-exempt** | Address charged no transfer fee; S7/S9 `isFeeExempt` applies only to `transferFrom`, not `sell()` |
| **Honeypot (token)** | Token whose code lets holders buy but not (profitably) sell |
| **IOC** | Indicator of compromise; here, a recurring hard-coded address or code shape |
| **Latent role chain** | Sequence of setters that must run before a privileged role exists ([control plane §1.4](../analysis/control-plane.md#14-latent-four-step-role-chains)) |
| **Price impact** | Execution slippage relative to the pre-trade spot price, $1-(\Delta y/\Delta x)/(y/x)$ |
| **Round-trip retention** | $\rho=(1-i_b)(1-i_s)$ for a buy then sell; not $\gamma^2(1-i_b)(1-i_s)$ |
| **Selector / pragma** | Function signature hash / Solidity version constraint; a pragma is not a security claim |
| **UUPS** | Upgradeable proxy pattern where the implementation holds the upgrade authoriser; here `_authorizeUpgrade` is acceptive of fixed address **A** |
| **Verified source** | Explorer-provided source that recompiles to the deployed bytecode; still requires behavioural review |

## Address labels

| Label | Address | One-line role |
|---|---|---|
| **A** | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra `onlyOwner` caller; upgrade key in S8/S9/S14 |
| **B** | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Role-chain seeder |
| **C** | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Negative guard target via `exchange()`; purpose unknown |
| **D** | `0x63e67a280645edf97880c1df03c8301b151c4668` | `onlyAuthorize` caller in S6–S9; `_miu` root in S8 |
| **P** | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Fragment-assembled `onlypublic` / `naming` gate |

Full evidence: [IOC table](../analysis/control-plane.md#2-ioc-address-table).

## References

Topical material (external links are provided as orientation only; none were fetched or verified for this handbook):

* Trail of Bits, *not-so-smart-contracts* — `honeypots/`
* thec00n, *smart-contract-honeypots*
* misterch0c, *Solidlity-Vulnerable* — `honeypots/`
* Medium / Hackernoon articles on Ethereum honeypots (titles listed in the archived `HONEYPOTS-ON-BLOCKCHAIN-README.md`)
* Slide deck *Smart contract honeypots on blockchain* (as cited by the pre-existing repository)

Internal reading order:

1. [Getting started](../guides/getting-started.md)
2. [Taxonomy](taxonomy.md) and [control plane](../analysis/control-plane.md)
3. [Math reference](math.md) and [risk indicators](../guides/risk-indicators.md)
4. [Detection playbook](../guides/detection-playbook.md)
5. [Classic catalog](classic-honeypots.md) — sources not attached
6. [Errata](../analysis/errata.md) for corrections to the earlier documentation

## Scope note

This handbook contains analysis and detection guidance only. It does not provide deployment parameters, configuration recipes or advice on avoiding detection. See [SECURITY](../SECURITY.md).
