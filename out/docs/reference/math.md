# Mathematical Reference

Equations used throughout this handbook, each with a worked, numerically checked example. Notation is collected at the end. Math renders on GitHub via `$$ … $$`.

> All numeric examples in this file were reproduced with a short Python script (exact integer arithmetic where on-chain integers are involved). Figures such as `0.9988` are rounded to four decimals.

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

A Uniswap-V2-style pool holds reserves $x$ (token) and $y$ (quote asset, e.g. ETH) and preserves

$$x \cdot y = k$$

(up to fees). With a swap fee $f$ (0.3 % ⇒ $f = 0.003$) and $\gamma = 1 - f$, selling $\Delta x$ tokens into the pool returns

$$\Delta y = \frac{\gamma\,\Delta x\; y}{x + \gamma\,\Delta x}$$

**Spot price** (quote per token): $p = y / x$.

**Price impact** of a sell of size $\Delta x$:

$$\text{impact}(\Delta x) = 1 - \frac{\Delta y/\Delta x}{y/x} = 1 - \frac{\gamma\,x}{x + \gamma\,\Delta x} = \frac{\gamma\,\Delta x + (1-\gamma)\,x}{x + \gamma\,\Delta x}$$

**Worked example.** Pool with $x = 10^6$ tokens and $y = 100$ ETH, $f = 0.3\,\%$. Selling $\Delta x = 10^6$ tokens (a trade equal to the whole token reserve) returns

$$\Delta y = \frac{0.997\cdot 10^6 \cdot 100}{10^6 + 0.997\cdot 10^6} \approx 49.92\ \text{ETH}$$

i.e. about half of the pool's ETH.

## 2. Fees, taxes and the round-trip multiplier

Let a token charge buy tax $\tau_b$ and sell tax $\tau_s$ (each in $[0,1]$). A holder who buys with value $V$ and immediately sells everything, ignoring pool fee and price impact, ends with

$$V_{\text{out}} = V\,(1-\tau_b)(1-\tau_s)$$

**Worked example.** $\tau_b = 5\,\%$, $\tau_s = 10\,\%$ ⇒ multiplier $0.95 \times 0.90 = 0.855$ (a 14.5 % round-trip loss before pool fees).

**Total-loss limit.** If $\tau_s = 1$ the multiplier is $0$ for every $\tau_b$. Several contracts in this repository cap fees at **100 %** (`require(newSellFee <= 100)`), so a privileged caller can move $\tau_s$ from $0$ to $1$ in a single transaction — see [Session 6](../contracts/session-06-switchable-honeypot-mode.md).

**Asymmetric fee path.** If the fee is only charged inside `transferFrom` (router-initiated sells) and not inside `transfer` (pool-initiated buys), then

$$\tau_b = 0,\qquad \tau_s = s,\qquad \text{round-trip} = 1 - s$$

A `transfer`-only test (wallet to wallet) will measure $0$ % tax and miss it. Always test through the router.

## 3. Sellability predicate and honeypot classification

Model a token's transfer rule as a predicate $P(h, a, c)$ — *holder* $h$, *amount* $a$, *calling context* $c$ (direct call, router call, …) — that is true iff the transfer succeeds. A token is **sell-restricted** if there exists an ordinary holder $h \notin \mathcal{W}$ (the privileged set) with

$$P(h,\,a,\,c_{\text{router}}) = \text{false}\quad\text{for all } a \in (0, \text{balance}(h)]$$

while $P(h, a, c_{\text{direct}})$ may be true. Examples of $P$ in this repository:

| Session | Predicate (for $h \notin \mathcal{W}$) |
|---|---|
| 1–3 | $P = \mathbb{1}[\texttt{allow}[h]]$ in `transferFrom`; `transfer` unrestricted |
| 4 | $P = \texttt{condition}(h,a)$; with no setter for the limits, $\texttt{condition} \equiv \text{false}$ |
| 5, 8 | $P = \lnot\,\texttt{isBlacklisted}[h]$ (per-address, owner-controlled) |
| 6, 7, 9 | $P \equiv \text{true}$ but the amount received is $a(1-\tau_s)$ with $\tau_s \in [0,1]$ |

**Empirical test (preferred over reading code).** On a fork, with a fresh funded address $h$, run *buy → approve → router sell*. Let $q_{\text{in}}$ be the quote paid and $q_{\text{out}}$ the quote received. Define the realised round-trip

$$\rho = \frac{q_{\text{out}}}{q_{\text{in}}}$$

and the *expected* round-trip from pool maths alone, $\rho_0 = \gamma^2 \cdot (1 - \text{impact}_b)(1 - \text{impact}_s)$. Flag when

$$\text{sell reverts}\quad\lor\quad \rho < \rho_0 - \varepsilon$$

with $\varepsilon$ a tolerance (1–2 % is typical). **Repeat from a second address and after a delay or privileged call**: predicates keyed on holder identity, time, or owner-set state (Sessions 5 and 6–9) pass a single fresh-address test.

## 4. Supply invariants and the double-credit defect

A well-formed fixed-supply token satisfies

$$\sum_{a} \texttt{balanceOf}(a) = \texttt{totalSupply}$$

Mint adds $m$ to both sides; burn subtracts from both. The helpers `_transferTo` and `_balanceView` in Sessions 1–10, 13, 14 do this instead:

```solidity
balances[_to] += _amount;  emit Transfer(address(0), _to, _amount);
balances[_to] += _amount;  emit Transfer(address(0), _to, _amount);
```

For one call with amount $a$:

$$\Delta\!\left(\sum \texttt{balanceOf}\right) = 2a,\qquad \Delta\,\texttt{totalSupply} = 0,\qquad \text{events emitted} = 2 \times \text{Mint}(a)$$

so the invariant gap grows by $2a$ per call and indexers that sum `Transfer` events see $2a$ minted while `totalSupply()` never moves. A holder-balance audit (sum of balances − `totalSupply`) detects this; so does comparing event-derived supply with `totalSupply()`.

Functions that *assign* instead of add (`balances[x] = v`, Sessions 1–4) break the invariant in either direction, because they ignore the prior balance of `x`.

## 5. Dilution and pool-drain from hidden minting

**Dilution.** A holder with balance $s$ of supply $S$ owns fraction $s/S$. After an unreported mint of $m$ tokens,

$$\frac{s}{S} \;\longrightarrow\; \frac{s}{S+m}$$

Example: $s = 10^5$, $S = 10^6$, $m = 10^6$ ⇒ $10\,\% \to 5\,\%$.

**Pool drain.** If the minter sells $m$ freshly minted tokens into a pool with reserves $(x, y)$ the quote asset extracted is $\Delta y(m) = \dfrac{\gamma\,m\,y}{x + \gamma\,m}$, so the fraction of the pool's quote reserve removed is

$$\frac{\Delta y}{y} = \frac{\gamma m}{x + \gamma m}\;\xrightarrow{\;m\to\infty\;}\;1$$

| Minted $m$ (tokens) | Fraction of pool's ETH removed ($x=10^6$, $\gamma=0.997$) |
|---:|---:|
| $10^{6}$ | 0.4992 |
| $10^{7}$ | 0.9088 |
| $10^{9}$ | 0.9990 |
| $10^{12}$ | 0.99999 |

Because the cost of minting is zero, **any reachable uncapped mint is equivalent to the right to withdraw essentially all pool liquidity.** This is why mint reachability, not mint size, is the quantity to audit. Sessions with such paths: 1–10, 13, 14 (see the [control-plane analysis](../analysis/control-plane.md)).

## 6. Classic honeypot arithmetic

These relate to the contracts in [`Honeypots-on-Blockchain`](classic-honeypots.md).

### 6.1 Unfair equation (`01_unfair_equation.sol`)

```solidity
function multiplicate(address adr) public payable {
    if (msg.value >= this.balance) { adr.transfer(this.balance + msg.value); }
}
```

Inside a payable call, `this.balance` already includes `msg.value`. With prior balance $B$ and value $v$:

$$v \;\ge\; B + v \iff B \le 0$$

The condition is true only when the contract held nothing beforehand — exactly when there is no money to win. For every $B > 0$ the payout never triggers.

### 6.2 Math trick (`10_math_trick.sol`)

Each racer's per-call limit starts at $L_0 = 50$ finney and halves after every deposit: $L_k = L_0 / 2^k$. The cumulative score after $n$ deposits is bounded by

$$\sum_{k=0}^{n-1} L_0\,2^{-k} \;=\; 2L_0\left(1 - 2^{-n}\right) \;<\; 2L_0 = 100\ \text{finney} = \text{SCORE\_TO\_WIN}$$

so the win condition `score >= 100 finney` is unreachable for any finite $n$. With integer division in wei the bound is even tighter: the deposits $5\times10^{16}, 2.5\times10^{16}, \dots$ stop at the `msg.value > 1 wei` floor after 55 steps and total $99{,}999{,}999{,}999{,}999{,}979$ wei — **21 wei short** of $10^{17}$.

### 6.3 Early termination by integer wrap (`07`, `07a`)

In Solidity < 0.5, `var i = 1;` infers the *smallest* type that holds the literal — `uint8`. Increments wrap modulo $2^8 = 256$.

* `07_early_termination.sol`: `i1` counts $1,2,\dots,255$, then $255+1 \equiv 0 \pmod{256}$; the loop test `i1 < i2` fires and `i2 = 255` is paid. Payout $= 255$ wei regardless of the deposit.
* `07a_early_termination.sol`: `multi = i*2` is evaluated in `uint8`. For $i = 127$, $multi = 254$; for $i = 128$, $multi = 256 \bmod 256 = 0 < 254$ ⇒ `break`. Payout $= 254$ wei.

Both results were reproduced by simulating the wrap in Python.

### 6.4 Storage overwrite (`04_storage_overwrite.sol`)

An uninitialised local `Game game;` is a *storage* pointer to slot 0. Writing `game.player = msg.sender` stores the caller's address in slot 0, which is `secretNumber`; `game.number = number` overwrites slot 1 (`lastPlayed`). The win test `number == secretNumber` compares a value $\le 10$ with a 160-bit address, so

$$\Pr[\text{win}] = 0\quad\text{for every caller whose address} > 10.$$

## 7. Notation

| Symbol | Meaning |
|---|---|
| $x, y$ | Pool reserves of token and quote asset |
| $k$ | Constant product $x\cdot y$ |
| $f,\ \gamma$ | Pool fee and $\gamma = 1-f$ |
| $\tau_b,\ \tau_s$ | Token-level buy / sell tax |
| $P(h,a,c)$ | Transfer-success predicate (§3) |
| $\mathcal{W}$ | Privileged / allow-listed address set |
| $\rho,\ \rho_0$ | Realised and model-expected round-trip multiplier |
| $S,\ s,\ m$ | Total supply, a holder's balance, a minted amount |
| $B,\ v$ | Prior contract balance, `msg.value` |
