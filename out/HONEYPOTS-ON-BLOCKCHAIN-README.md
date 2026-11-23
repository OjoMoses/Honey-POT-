# A Pot of Smart Contract Honeypots

Fourteen Ethereum bait contracts collected from the first pages of search results: each looks like an easy way to take Ether and is built so the taker loses. Use them to learn **how the deception works** and how to spot it; they are written for Solidity 0.4.x and are not meant to be deployed.

> Run on a local chain only. Never send real funds to a contract from this repository or to any copy of it.

## Contracts

| File | Contract | Trick | Why it can never pay out |
|---|---|---|---|
| `01_unfair_equation.sol` | `MultiplicatorX3` | `this.balance` already includes `msg.value` | $v \ge B+v$ only if $B \le 0$ |
| `02_hidden_call.sol` | `Gift_1_ETH` | State frozen by a hidden contract-to-contract call | guard flag set before victims arrive |
| `02a_hidden_call.sol` | `G_GAME` | Answer hash replaced by the poster | winning condition mutable |
| `03_white_spaces.sol` | `TestToken` | Code pushed off-screen by whitespace | after a block height only the owner may withdraw |
| `04_storage_overwrite.sol` | `CryptoRoulette` | Uninitialised struct pointer hits slot 0 | `secretNumber` overwritten by the caller's address |
| `05_owner_overwrite.sol` | `ICO_Hold` | Shadowed `Owner` variable | `isOwner()` reads the parent's variable |
| `06_fake_api.sol` | `Private_Bank` | Logger reverts, undoing reentrancy | whole transaction unwinds |
| `07_early_termination.sol` | `Test1` | `var` is `uint8` | loop ends at 255 → pays 255 wei |
| `07a_early_termination.sol` | `For_Test` | `i*2` wraps in `uint8` | pays 254 wei |
| `08_fake_transfer.sol` | `X2_FLASH` | `call.value(x)` without `()` | nothing is sent |
| `09_innocent_log.sol` | `firstTest` | `delegatecall` rewrites `adr` | payout goes to the owner |
| `10_math_trick.sol` | `RACEFORETH` | Halving per-deposit cap | series sums below the target |
| `11_old_compiler.sol` | `DividendDistributorv3` | Empty string dropped by Solidity 0.4.13 | funds go to `owner` |

Full write-ups, mechanisms, detection tips and equations: **Honeypot Research Handbook** → [Classic honeypot catalog](docs/reference/classic-honeypots.md) and [Math §6](docs/reference/math.md#6-classic-honeypot-arithmetic).

## Tutorials, repositories and news

*(unchanged from the original README)*

- [The phenomenon of smart contract honeypots](https://medium.com/coinmonks/the-phenomena-of-smart-contract-honeypots-755c1f943f7b)
- [An analysis of a couple Ethereum honeypot contracts](https://medium.com/coinmonks/an-analysis-of-a-couple-ethereum-honeypot-contracts-5c07c95b0a8d)
- [Hacking the Hackers: Honeypots on Ethereum Network](https://hackernoon.com/hacking-the-hackers-honeypots-on-ethereum-network-5baa35a13577)
- [Dissecting an Ethereum Honey Pot](https://medium.com/coinmonks/dissecting-an-ethereum-honey-pot-7102d7def5e0)
- [The Sneakiest Ethereum "Scam" (honeypot) Ever](https://hackernoon.com/the-sneakiest-ethereum-scam-ever-6dc138061235)
- Repos: [thec00n/smart-contract-honeypots](https://github.com/thec00n/smart-contract-honeypots), [trailofbits/not-so-smart-contracts](https://github.com/trailofbits/not-so-smart-contracts/tree/master/honeypots), [misterch0c/Solidlity-Vulnerable](https://github.com/misterch0c/Solidlity-Vulnerable)
- Presentation: [Smart contract honeypots on blockchain](https://www.slideshare.net/YaochiehHu/smart-contract-honeypots-on-blockchain)
