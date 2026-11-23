# Glossary and References

## Glossary

| Term | Meaning |
|---|---|
| **AMM** | Automated market maker; a pool pricing swaps by a formula ([Math §1](math.md#1-constant-product-amm)) |
| **Allow-list / whitelist** | Mapping of addresses exempt from a restriction ($\mathcal{W}$) |
| **Blacklist** | Mapping of addresses barred from transferring |
| **Bait contract** | Contract that appears to let a taker withdraw funds but is built so the taker loses |
| **Control plane** | The set of privileged functions and the paths that reach them |
| **Cosmetic renounce** | `renounceOwnership()` present but another route to the same powers remains |
| **Double credit** | Adding the same amount to a balance twice without raising `totalSupply` |
| **Fee-exempt** | Address charged no transfer fee |
| **Honeypot (token)** | Token whose code lets holders buy but not (profitably) sell |
| **IOC** | Indicator of compromise; here, a recurring hard-coded address or code shape |
| **Latent role chain** | Sequence of setters that must run before a privileged role exists ([Control plane §2](../analysis/control-plane.md#2-the-latent-role-chain)) |
| **Pair / router** | Uniswap-V2-style pool contract and the contract users call to swap |
| **Round-trip multiplier ($\rho$)** | Quote received after buying and selling back, divided by quote spent |
| **UUPS** | Universal Upgradeable Proxy Standard; upgrade logic lives in the implementation |
| **Wrap-around** | Integer overflow modulo $2^n$ in Solidity < 0.8 or inside `unchecked` |

## References

Primary sources cited by the `Honeypots-on-Blockchain` repository:

* *The phenomenon of smart contract honeypots* — Medium / Coinmonks
* *An analysis of a couple Ethereum honeypot contracts* — Medium / Coinmonks
* *Hacking the Hackers: Honeypots on Ethereum Network* — Hackernoon
* *Dissecting an Ethereum Honey Pot* — Medium / Coinmonks
* *The Sneakiest Ethereum "Scam" (honeypot) Ever* — Hackernoon
* Trail of Bits, `not-so-smart-contracts/honeypots`
* thec00n, `smart-contract-honeypots`; misterch0c, `Solidlity-Vulnerable`
* Slides by the repository author: *Smart Contract Honeypots on Blockchain* (SlideShare)

Standards and tools: EIP-20 (token), EIP-1967 (proxy storage slots), ERC-1822 (UUPS), Uniswap V2 whitepaper (constant-product AMM), Foundry book (`vm.createSelectFork`, `vm.prank`).

> URLs for the Medium/Hackernoon articles are listed in the original repository README and were not re-verified for this handbook.
