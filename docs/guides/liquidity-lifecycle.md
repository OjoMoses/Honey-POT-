# Liquidity Lifecycle

How a token's liquidity moves from launch to exit, and what to review at each stage. Concepts are generic to Uniswap-V2-style pools; equations are in [Math §1–2](../reference/math.md#1-constant-product-amm).

## Stages

| Stage | What happens | Review question |
|---|---|---|
| **1. Launch** | Deployer mints supply and creates a pair; reserves $(x_0,y_0)$ are seeded | Who holds the supply? Is trading gated while `LiquiduniswapV2Pair == 0`? See [S10](../contracts/session-10-normal-meme-token.md) L780–783. |
| **2. Liquidity provision** | LP tokens are minted to the provider | Where do LP tokens sit? A function named `LockLPToken()` proves nothing — [S6](../contracts/session-06-switchable-honeypot-mode.md) L281–282 is empty. |
| **3. Open trading** | Buys deliver tokens from the pair via `transfer`; sells call `transferFrom` through the router | Do the two paths apply different rules or fees? See [Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier) and S6 L73–82 vs L200–224. |
| **4. Steady state** | Fees, blacklists and limits can change | Who can call the setters? A 100 % ceiling is reachable in S6, S7 and S9. S5/S8 blacklists are writable after launch. |
| **5. Exit** | Hidden mint or balance overwrite drains the pool | Any reachable uncapped mint removes fraction $\gamma m/(x+\gamma m)$ of the quote reserve; [Math §5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting). S14 also under-reports supply. |

## Review points by mechanism

* **Sell path identity.** A router sell is a `transferFrom`, not a `transfer`. In S1–S3 the former requires `allow[_from]`; in S6–S9 only the former charges `sellFee`. Counting `transfer` as "the sell path" misses both.
* **State dependence.** Lists and limits are writable. A clean buy/sell at block $N$ says nothing about block $N+1$ after a privileged `zap`, `blacklist` or `setting` call.
* **Supply accounting.** Compare `totalSupply()` with the sum of balances and with zero-address transfer events. S14's public `totalSupply` is a separate counter from ERC-20's private `_totalSupply` ([S14](../contracts/session-14-v2-unlimited-supply-meme-token.md)).
* **Upgrade surface.** In S8, S9 and S14 an A-accepting `_authorizeUpgrade` survives ownership renounce. Record proxy admin and first initializer caller ([control plane §3](../analysis/control-plane.md#3-cosmetic-renounce-and-upgrade-keys)).

## What this page does not provide

No deployment parameters, liquidity-lock recipes or timing guidance. It is a checklist of *questions to ask* when reviewing an already-deployed or source-available token, following the [detection playbook](detection-playbook.md).
