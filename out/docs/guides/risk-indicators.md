# Risk Indicators

Concrete, testable red flags. Each row says what to look for, why it matters, and how to confirm it. Severity follows the [taxonomy](../reference/taxonomy.md#severity-model).

## Code-level indicators

| Indicator | Why it matters | Confirm with | Severity |
|---|---|---|---|
| `address(<very large decimal>)` in a `require` | Hides a privileged address from hex search | Scanner field `decimal_address_literals`; decode with `hex()` | Critical |
| `uint160(…) << 128 \| 96 \| 64 \| 32` in a `pure` function returning an address | Address assembled at runtime | Scanner `address_assembled_from_fragments` | Critical |
| `onlyOwner` that also accepts a literal address | Renounce is cosmetic | Read the modifier; call a gated function after `owner = 0` on a fork | Critical |
| `balances[x] = v` (assign, not add) | Overwrites balances incl. the pair's | Scanner `balance_overwrites` | Critical |
| Two consecutive credits of the same amount | $\sum b \ne$ `totalSupply` | Scanner `double_credit_helpers`; compare supplies | Critical |
| `setMember → setUser → setMod → setAdm` | Dormant privileges activate later | Trace to an EOA | High |
| `require(fee <= 100)` | 100 % is a legal setting | Read setters; test at 100 % on a fork | High |
| `transfer` and `transferFrom` differ | Wallet tests miss router-path rules | Router sell test | High |
| Blacklist mapping checked on the **sender** | Selective sell block | Test after blacklisting a fresh address | High |
| Public `initialize` without `_disableInitializers` | First caller takes ownership | Read proxy deployment txs | High |
| View-sounding names that write state; empty functions with reassuring names (`LockLPToken`) | Misleading review surface | Read bodies | Medium |
| Error strings that do not match the check | Obfuscation | Read | Medium |
| `var`, narrow loop counters, `delegatecall` to mutable address | Classic bait mechanics | [Catalog](../reference/classic-honeypots.md) | High |

## Behavioural indicators

* Router sell reverts or returns far less than $\rho_0$ ([Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification)).
* Supply sum from `Transfer(0x0, …)` events exceeds `totalSupply()`.
* Calls to the IOC addresses ([A–D, P](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers)) in the contract's internal-transaction history.
* A liquidity pair created by the deployer with LP tokens left in an EOA.

## Marketing indicators (weak, but common)

* Claims of "undetectable", "scanner-proof" or "bypasses honeypot checkers".
* "Renounced" or "non-honeypot" labels with no on-chain evidence.
* Pressure to buy before a "launch" or unlock.

These do not prove anything on their own; they justify running the [playbook](detection-playbook.md) before interacting.
