# Hidden Control-Plane Analysis

Most contracts in this repository contain privileges that are not visible from function names, modifiers or the `owner` variable. This page documents how those privileges are encoded so reviewers can recognise them in *any* token, not only these. Findings come from reading the source and from the bundled [indicator scanner](../guides/detection-playbook.md#2-static-triage-scanner).

> Scope note: this page is an analyst's reference. It explains how the code is structured so it can be flagged; it is not a deployment or configuration guide.

## 1. Four techniques, in order of how often they hide a risk

### 1.1 Privileged addresses written as decimal integers

```solidity
modifier onlyOwner() {
    require(msg.sender == address(178607940065137046348733521910879985571412708986)
            || (msg.sender == owner && msg.sender != exchange()));
    _;
}
```

A 160-bit address is written as a base-10 number, so a search for `0x…` in a block explorer or in a scanner's address-literal rule finds nothing. Convert with `hex(n)` (Python) or `cast to-hex`. The decimals in this repository decode to:

| Label | Decimal literal | Address | Role in code |
|---|---|---|---|
| **A** | `178607940065137046348733521910879985571412708986` | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Always accepted by `onlyOwner` / `onlyAuthorized`, whether or not `owner` was renounced |
| **B** | `686197854011229533619447624007587113080310915153` | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Only caller of `setMember` / `setUsdtPair`, the first link of the role chain (§2) |
| **C** | `17860794006513704634733521910879985571412708986` | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()` / `contracts()`; excluded from the `Exchanges` / `info` guards and from the deployer-owner path |
| **D** | `570329899025738970963394674811034510039273195112` | `0x63e67a280645edf97880c1df03c8301b151c4668` | Accepted by `onlyAuthorize` (Sessions 6–9) — gates fee setting and minting helpers |
| **P** | *assembled at runtime* | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Returned by `publics()`; gates `onlypublic` functions |

A, B and C appear in every file that carries the pattern (Sessions 1–10, 13, 14); D is added in Sessions 6–9. Treat these as indicators of compromise when screening deployed bytecode.

### 1.2 An address assembled from fragments

```solidity
uint160 core = (uint160(0x7addAd09) << 128) | (uint160(0xcbd98D97) << 96)
             | (uint160(0xEC3dA7a0) << 64)  | (uint160(0x088EAdFE) << 32)
             |  uint160(0x5801C336);
return address(core);
```

Five 32-bit constants named `universal`, `uni`, `cake`, `inch`, `others` read like DEX-router labels but combine to the single privileged address **P**. No contiguous `0x…40-hex-digit…` string ever appears in the source or the bytecode's constant pool, so literal matching fails. Detect with the shape: `uint160(...) << 128|96|64|32` inside a `pure` function that returns an `address` used in a `require`.

### 1.3 A *negative* guard that excludes one address

```solidity
modifier Exchanges() { require(msg.sender != exchange()); _; }
```

Used on mint-style internals (`_proof`, `_scale`, `_printbrr`, `_transferTo`). Ordinary guards say *who may*; this one says *who may not*, which makes the function callable by everybody else who reaches it. The purpose of address **C** cannot be established from source alone; the review rule is simply: a hard-coded exclusion on a mint path is a red flag, because it shapes how the function behaves for exactly one caller (for example a simulation or analyser running from that address).

### 1.4 Deliberately misleading names and strings

| Observed | Reality |
|---|---|
| `viewBalance(address,uint256)` | Writes to balances (double-credit) — not a view |
| `compute`, `decimal`, `symbols`, `rewire`, `proof`, `scaling`, `FeesView` | Mint functions |
| `LockLPToken()` | Empty body; locks nothing |
| `"Recipient is Gwei"` | Error text for a blacklisted **sender** |
| Comments such as `keccak256 -> 98386…` and `OpenZeppelin256 -> 96e8…` | Decorative; not hashes of anything used by the code |

## 2. The latent role chain

Sessions 1–4 and 5–10, 13, 14 define four setters that each accept only the *previous* role:

```text
 B ──setMember/setUsdtPair──▶ _mbr / _usdtPair
                                   │ setUser
                                   ▼
                                 _user ──setMod──▶ _mod ──setAdm──▶ _adm
                                                                    │
                          mint, fee control, allow-list, balance writes
```

Two consequences for reviewers:

1. **The privilege is dormant at deployment.** `_mbr`, `_user`, `_mod`, `_adm` are all `address(0)` after construction, so static analysers and fork simulations performed *before* the chain is walked see these functions as unreachable. A clean simulation result at time $t_0$ says nothing about $t_1 > t_0$.
2. **Reachability must be evaluated against the whole chain**, not against `owner`. The correct audit question is "who can ever become `_adm`?" — here, only holder **B**, one transaction at a time.

The same pattern is the reason `renounceOwnership()` is meaningless in these files: `onlyOwner` accepts **A** unconditionally, so after `owner = address(0)` every owner-gated function remains callable by A.

## 3. What the privileges allow (by capability)

| Capability | Functions (name varies by session) | Effect | Equation |
|---|---|---|---|
| Unbounded mint | `proof`, `rewire`, `approval(uint256)`, `scaling`, `compute`, `symbols`, `decimal`, `print` | `totalSupply` and a balance both increase | [Math §5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting) |
| Balance overwrite | `mint(address,uint256)` (S1–3), `adjust`, `approveAndCall`, `_computing`, `_approvals` | `balances[x] = v`, destroying or fabricating any balance — including the pair's | invariant break, [Math §4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect) |
| Double credit | `transferTo`, `viewBalance` | balance $+2a$, supply $+0$ | [Math §4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect) |
| Sell restriction | allow-list (S1–4), blacklist (S5, S8, S10, S13, S14), fee ≤ 100 % (S6, S7, S9) | holder cannot exit or exits at a loss | [Math §2–3](../reference/math.md#3-sellability-predicate-and-honeypot-classification) |
| Takeover of proxy | unprotected `initialize` + `_authorizeUpgrade` (S8, S9, S14) | first caller becomes owner; owner (and A) may upgrade the logic | n/a |

## 4. Session grouping by structural lineage

```text
Family 1  (allow-list sell gate)      S1 → S2 → S3
Family 2  (anti-bot condition)         S4
Family 3  (blacklist, BEP-20)          S5 → S8 (UUPS port)
Family 4  (fee switch)                 S6 → S7 (+fee-exempt) → S9 (UUPS port of S7)
Family 5  (OZ ERC-20 + trade limits)   S10 → S13 (+print) → S14 (UUPS port of S13)
Clean     (no indicators)              S11, S12, S15
```

"→" means *derived from* by diff: the later file keeps the earlier file's control plane and adds or ports it.

## 5. Clean contracts — what "clean" means

[S11](../contracts/session-11-ownership-renounce-meme-token.md), [S12](../contracts/session-12-auto-ownership-renounce-meme-token.md) and [S15](../contracts/session-15-v2-auto-ownership-renounce-meme-token.md) contain no hard-coded addresses, no assembled addresses, no role chain, no mint after construction and (S12, S15) call `renounceOwnership()` inside the constructor, leaving no privileged function. That is a verdict on the *source in this repository*; deployed copies must still be compared byte-for-byte.
