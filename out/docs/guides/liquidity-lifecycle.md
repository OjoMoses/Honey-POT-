# Liquidity Lifecycle

How a token's liquidity moves from launch to exit, and what to check at each stage. Concepts are generic to Uniswap-V2-style pools; equations are in [Math §1–2](../reference/math.md#1-constant-product-amm).

## Stages

| Stage | What happens | Review question |
|---|---|---|
| **1. Launch** | Deployer mints supply and creates a pair; seeds reserves $(x_0, y_0)$ | Who holds the supply? Is trading gated (e.g. while `LiquiduniswapV2Pair == 0` only the owner may transact — [S10](../contracts/session-10-normal-meme-token.md))? |
| **2. Liquidity provision** | LP tokens minted to the provider | Where do the LP tokens sit — wallet, lock contract, burn address? A function named `LockLPToken()` proves nothing ([S6](../contracts/session-06-switchable-honeypot-mode.md) has an empty one). |
| **3. Open trading** | Buys deliver tokens from the pair through `transfer`; sells call `transferFrom` via the router | Do the two paths apply different rules or fees? ([Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier)) |
| **4. Steady state** | Price follows $p=y/x$; holders and fees accrue | Is supply stable? Compare event-derived and reported supply ([Math §4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect)). |
| **5. Exit risk** | LP removal, mint-and-sell, blacklisting, fee raise | Which privileged action converts a healthy pool into a one-way pool? |

## Exit mechanics

**LP removal.** Removing a fraction $\lambda$ of the LP supply returns $\lambda x$ and $\lambda y$. A single provider who owns all LP tokens can withdraw the whole pool; locks or burns are the only mitigations, and both are observable on chain.

**Mint-and-sell.** If a reachable mint exists, the extractable share of $y$ is $\gamma m/(x+\gamma m)$ ([Math §5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)) — no LP ownership is needed.

**Fee raise.** Moving $\tau_s$ to 100 % turns every subsequent sale into a transfer of the full amount to the contract ([S6](../contracts/session-06-switchable-honeypot-mode.md), [S7](../contracts/session-07-whitelist-switchable-honeypot.md), [S9](../contracts/session-09-v2-whitelist-switchable.md)); holders cannot exit and the pool's ETH is unaffected.

**Blacklist.** Barring a seller removes one holder's exit without any visible market change ([S5](../contracts/session-05-blacklist-detector-proof-honeypot.md), [S8](../contracts/session-08-v2-blacklist-detector-proof.md)).

## Evidence to collect

* Pair address, reserves over time, LP-token holders and lock status
* Every transaction by an address named in the [control-plane IOC table](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers)
* `Transfer` events from the zero address (mints) and their sum against `totalSupply()`
