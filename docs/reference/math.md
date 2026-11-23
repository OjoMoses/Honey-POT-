# Mathematical Reference

Every quantitative claim in this handbook is reproduced by [`tools/verify_numbers.py`](../../tools/verify_numbers.py) using exact integers and `fractions.Fraction` (standard library only). The saved output is [`reports/numbers.txt`](../../reports/numbers.txt); 62 checks pass. No floating point is used for on-chain quantities — decimals such as `0.5008` are rounded only for display.

> The 14 classic bait-contract sources are **not in the attached archive**. Section 6 verifies the *arithmetic* of those claims independently, but the contract behaviour itself remains an unverified pre-existing claim ([classic catalog](classic-honeypots.md)).

## Contents

1. [Constant-product AMM](#1-constant-product-amm)
2. [Fees, taxes and the round-trip multiplier](#2-fees-taxes-and-the-round-trip-multiplier)
3. [Sellability predicate and honeypot classification](#3-sellability-predicate-and-honeypot-classification)
4. [Supply invariants and the double-credit defect](#4-supply-invariants-and-the-double-credit-defect)
5. [Dilution and pool-drain from hidden minting](#5-dilution-and-pool-drain-from-hidden-minting)
6. [Classic honeypot arithmetic](#6-classic-honeypot-arithmetic)
7. [Notation](#7-notation)

---

## 1. Constant-product AMM

A Uniswap-V2-style pool holds reserves $x$ (token) and $y$ (quote asset). With fee fraction $f$ and $\gamma = 1 - f$, selling $\Delta x$ tokens into the pool returns

$$
\Delta y = \frac{\gamma\,\Delta x\,y}{x + \gamma\,\Delta x}.
$$

**Worked example (verified).** $x = 10^6$, $y = 100$, $f = 0.003$ (0.3 %), $\Delta x = 10^6$:

$$
\Delta y = \frac{0.997 \cdot 10^6 \cdot 100}{10^6 + 0.997\cdot 10^6} = \frac{99\,700}{1\,997} \approx 49.9249.
$$

The pre-trade spot price is $y/x = 10^{-4}$ quote per token; the execution price is $\Delta y/\Delta x \approx 4.99249\times10^{-5}$. Price impact is

$$
i = 1 - \frac{\Delta y/\Delta x}{y/x} = \frac{1000}{1997} \approx 0.5008 \; (50.08\%).
$$

**Round-trip composition (corrected).** Buy with $q$ quote, then sell all received tokens. Let $i_b$ and $i_s$ be the buy-side and sell-side price impacts. The exact round-trip retention is

$$
\rho = \frac{q_{\text{out}}}{q_{\text{in}}} = (1-i_b)(1-i_s),
$$

**not** $\gamma^2(1-i_b)(1-i_s)$, which double-counts the fee. Verified values: buying $q=1$ yields $\frac{997000000}{100997}\approx 9871.5803$ tokens; selling them returns $\frac{99400900}{101991009}\approx 0.974605$ quote. Here $i_b\approx0.012842$, $i_s\approx0.012717$, $(1-i_b)(1-i_s)=\rho\approx0.974605$. The zero-impact limit is $\gamma^2=0.994009$; the double-counted expression would give $\approx0.968766$, which is wrong.

## 2. Fees, taxes and the round-trip multiplier

With multiplicative buy tax $\tau_b$ and sell tax $\tau_s$ applied to the *amount* (as in S6–S9, divisor 100), value retained across a full buy→hold→sell cycle is

$$
m = (1-\tau_b)(1-\tau_s), \qquad \text{loss} = 1-m = \tau_b + \tau_s - \tau_b\tau_s.
$$

Verified example: $\tau_b=0.05$, $\tau_s=0.10 \Rightarrow m = 0.95\cdot0.90 = \frac{171}{200}=0.855$, a $14.5\%$ loss. At $\tau_s=1$ ($100\%$), $m=0$ regardless of $\tau_b$: the seller receives nothing.

The contracts apply this in integer wei, not as an abstract percentage. For `amount = 1000`, `sellFee = 100` and divisor `100` (S6 L205, S7 L213–215, S9 L217–219):

$$
\texttt{fee} = \left\lfloor\frac{1000\cdot100}{100}\right\rfloor = 1000, \qquad a_{\text{recv}} = 1000 - 1000 = 0.
$$

`transfer` (S6 L73–82, S7 L75–84, S9 L86–95) charges no fee for the same amount: $a_{\text{recv}}=1000$. This **path asymmetry** is why a fresh-address test that only exercises wallet-to-wallet `transfer` cannot detect the fee gate. S7/S9 add `isFeeExempt[_from]`, but `sell()` (S7 L368–382, S9 L376–390) ignores that exemption and always charges `sellFee`.

## 3. Sellability predicate and honeypot classification

Let $b(a)$ be the balance of address $a$, $t$ the recipient, $v>0$ the amount and $P(h,t,v)$ the requirement for a transfer to succeed. A token is a *sellability honeypot* if, for a typical buyer $h$, $P$ is false on the router's `transferFrom` sell path while buys succeed. Four distinct constructions occur:

| Class | Predicate shape | Sessions | Evidence |
|---|---|---|---|
| Allow-list gate | $P \Rightarrow \texttt{allow}[h]$ (default false) | S1–S3 | S1 L176 |
| Permanent anti-bot lock | $P\Rightarrow\texttt{condition}\equiv\texttt{false}$ unless exempt | S4 | L557, L608/L610/L612 never assigned |
| Writable blacklist | $P\Rightarrow\neg\texttt{isBlacklisted}[h]$ | S5, S8, S10, S13, S14 | S5 L637; S8 L637; S10 L778 |
| Economic gate | $P\equiv\text{true}$, but $a_{\text{recv}}=v(1-s)$, $s\in[0,1]$ | S6–S9 | divisor 100, caps `<= 100` |

S10/S13/S14 add a fifth condition: while `LiquiduniswapV2Pair == 0`, $P\Rightarrow h=owner\lor t=owner$ (S10 L780–783); once the pair is set, pair→holder buys are constrained by $\texttt{minHolding}\le b(t)+v\le\texttt{maxHolding}$ (L785–787). Sells *to* the pair are not constrained by that band.

A clean baseline is $P\equiv\text{true}$ subject only to $b(h)\ge v$ and $t\ne 0$ (S11, S12, S15).

## 4. Supply invariants and the double-credit defect

For an ERC-20-style token the accounting invariant is

$$
\sum_{a} b(a) = S = \texttt{totalSupply}.
$$

A *double-credit* helper breaks it by adding the same amount twice without touching $S$. Verified with $v=777$:

$$
\Delta\sum b = 2v = 1554,\qquad \Delta S = 0,\qquad \text{number of mint-style events}=2.
$$

The helpers are `_transferTo` and `_balanceView` in S1–S10, S13, S14 (only one `_transferTo` in S4). Each emits two `Transfer(address(0), target, v)` events, so event-derived supply estimates diverge from the storage counter. Assignment helpers are a separate defect: `_mint` in S1–S3 assigns `balances[miner] = _value` rather than incrementing, so it can *overwrite* an existing balance. On 0.8.x (S3, S6–S10, S13, S14) doubled `+=` reverts on overflow instead of wrapping — a changed failure mode, not a fix.

S14 has a distinct reporting divergence: public `totalSupply` (L620, set only at L646) is a different variable from ERC-20's private `_totalSupply` (L209), which the mint helpers increase. Reported supply therefore does not reflect later minting ([S14](../contracts/session-14-v2-unlimited-supply-meme-token.md)).

## 5. Dilution and pool-drain from hidden minting

If a holder owns $s$ of $S$ tokens, an uncapped mint of $m$ reduces their share from $s/S$ to $s/(S+m)$. Verified: $s=10^5$, $S=10^6$, $m=10^6$ gives $10\%\to5\%$.

If the newly minted tokens are sold into a pool with token reserve $x=10^6$, the fraction of the quote reserve extracted is $\gamma m/(x+\gamma m)$ with $\gamma=0.997$. Exact verified values:

| Minted $m$ | Fraction drained |
|---|---|
| $10^6$ | 0.499249 |
| $10^7$ | 0.908842 |
| $10^9$ | 0.998998 |
| $10^{12}$ | 0.999999 |

$$
\lim_{m\to\infty}\frac{\gamma m}{x+\gamma m}=1.
$$

Therefore any *reachable, uncapped* mint is economically equivalent to a pool-drain key. In S13/S14, `print(uint256)` is public and `onlyOwner`; because `onlyOwner` also accepts fixed address **A** (S13 L122, S14 L709), renouncing the stored owner does not remove the key.

## 6. Classic honeypot arithmetic

Sources not attached; these checks validate the published arithmetic only.

### 6.1 Unfair equation (01_unfair_equation.sol)

In a payable call, `this.balance` already includes `msg.value = v`, so the published test $v\ge B+v$ is false for every prior balance $B>0$ and true only when $B=0$. Verified: with $B=v=10^{18}$, `False`; with $B=0$, `True`.

### 6.2 Math trick (10_math_trick.sol)

The cap starts at $L_0=50\,\text{finney}=5\cdot10^{16}$ wei and halves (floor) each deposit. Verified: 55 deposits before the cap reaches 1 wei; exact deposit sum $=99\,999\,999\,999\,999\,979$ wei; shortfall from $100\,\text{finney}=10^{17}$ wei is **21 wei**. The geometric bound $2L_0=10^{17}$ is approached but never reached. (An earlier draft stated a 1-wei shortfall; corrected here.)

### 6.3 Early termination by integer wrap (07-07a)

`var` inferred `uint8`; the loop's last value is 255, giving a 255-wei payout (verified). For `i*2 mod 256`, $127\cdot2\bmod256=254$ and $128\cdot2\bmod256=0$; the published 254-wei payout corresponds to $i=127$ (verified).

### 6.4 Storage overwrite (04_storage_overwrite.sol)

A guessed number is constrained to $1..10$, while an uninitialised storage pointer overwrites the secret with `msg.sender`, a 160-bit value. The smallest integer above 10 is 11; no value in the guess range can equal an address (verified trivially, source absent).

## 7. Notation

| Symbol | Meaning |
|---|---|
| $a$, $b(a)$ | Address and its token balance |
| $S$ | `totalSupply` |
| $v$, $t$, $h$ | Amount, recipient, holder/seller |
| $P(h,t,v)$ | Transfer predicate; must be true for the call to succeed |
| $\gamma$ | AMM retention factor $1-f$ |
| $x$, $y$ | Token and quote reserves |
| $\tau_b,\tau_s$ | Buy and sell tax rates; $s=\texttt{sellFee}/100$ |
| $i_b,i_s$, $\rho$ | Buy/sell price impact and round-trip retention |
| $\mathcal{W}$ | Allow/exempt set |
| A, B, C, D, P | Recurring fixed or assembled addresses; see [control plane](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers) |

> Scope: equations describe the code as written. No contract in this handbook was compiled, deployed or executed for this documentation; see the [detection playbook](../guides/detection-playbook.md#4-dynamic-test-on-a-fork) for the fork test that would confirm behaviour dynamically.
