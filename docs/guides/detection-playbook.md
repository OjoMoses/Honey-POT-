# Detection Playbook

A repeatable procedure for deciding whether a token or bait contract can trap a holder. Ordered cheapest to most expensive; stop when a step produces a confirmed finding. Analysis and detection only — see [SECURITY](../SECURITY.md).

## 0. Ground rules

* Work on a **local fork** or testnet with throw-away keys. Never connect a funded wallet to an unreviewed contract or dApp.
* Treat every label (`non-honeypot`, `renounced`, `audited`, `safe`, `V2`) as an unverified claim ([errata](../analysis/errata.md)).
* A negative result is **time-indexed**: record block number, chain and the exact state tested.
* Source lines in this handbook refer to the extracted LF copies; see [duplicate mapping](../analysis/errata.md#duplicate-copies-and-line-endings).

## 1. Provenance and bytecode

1. Obtain verified source **and** runtime bytecode. Recompile with the exact compiler version and settings; compare byte-for-byte, ignoring the metadata hash.
2. Identify proxies: EIP-1967 slots, `UUPSUpgradeable`, `delegatecall`. Review proxy admin and implementation; ask who can call `upgradeTo` / `_authorizeUpgrade`. S8, S9 and S14 use a public first-caller-wins `initialize` with no `_disableInitializers` ([control plane §3](../analysis/control-plane.md#3-cosmetic-renounce-and-upgrade-keys)).
3. For historical 0.4.x baits, use the exact compiler; behaviour such as `var` inference and dropped empty-string arguments depends on it ([classic catalog](../reference/classic-honeypots.md)).
4. Record the file hash and line count; the 15 contract line counts are listed in [`reports/numbers.txt`](../../reports/numbers.txt).

## 2. Static triage scanner

```bash
python3 -I tools/scan_indicators.py contracts/ --out reports/scanner.txt
python3 -I tools/scan_indicators.py contracts/ --json --out reports/scanner.json
```

The scanner is stdlib-only, strips comments while preserving line numbers, and reports these fields:

| Field | Meaning | Expected on attached corpus |
|---|---|---|
| `decimal_address_literals` | `address(<large decimal>)` and bare 38+-digit candidates, decoded to 40-hex | A/B/C in S1–S10, S13, S14; D added in S6–S9 |
| `address_assembled_from_fragments` | `uint160(…) << 128/96/64/32` OR chains decoded safely | P in the same 12 sessions; none in S11/S12/S15 |
| `modifiers_with_hardcoded_address` | Modifier bodies containing an address literal | `onlyOwner` family |
| `msgsender_ne_function_guards` | `msg.sender != f()` guards | `contracts()` / `exchange()` / `exchanger()` exclusions |
| `balance_overwrites` | Direct `balances[x] = …` writes | S1–S9: 1–5 each; S10/S13/S14: 0 (mint helpers used); S11/S12/S15: only the constructor assignment |
| `double_credit_helpers` | Two `+=` on the same lvalue with the same amount in one function | `_transferTo`, `_balanceView` in 12 sessions (one in S4) |
| `role_chain_setters` / `role_chain_edges` | `set*` functions and role-variable edges | 3 edges in S1–S10, S13, S14; S8 adds `setMedium` |
| `fee_cap_100` | `require(new*Fee <= 100)` | 10 hits each in S6, S7, S9 |
| `renounceOwnership`, `uups`, `initialize` | Cosmetic-renounce and takeover surface | UUPS in S8, S9, S14 |

**Interpretation.** A hit is a reason to read the cited lines; absence of hits is never proof of safety. Actively misleading constructs include `onlyAuthorize` (D) versus `onlyAuthorized` (A), view-sounding writers and empty `LockLPToken()`.

## 3. Manual review checklist by class

For each item, record the file and line or record "not found".

1. **Transfer paths.** Diff `transfer` against `transferFrom` and any internal `_transfer`. Note fee math, list checks, pair checks and order of requires.
2. **Modifiers.** Expand every guard into a boolean expression. Mark fixed-address disjuncts and negative guards separately.
3. **Addresses.** Decode every decimal literal with exact integer formatting; evaluate fragment assembly with a whitelist AST evaluator (the scanner does this). Compare against the [IOC table](../analysis/control-plane.md#2-ioc-address-table).
4. **Supply writers.** Search for `+=`, `-=` and `=` on supply and balances. Flag helpers without a cap and helpers that emit `Transfer(address(0),…)` while leaving supply unchanged ([Math §4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect)).
5. **Role reachability.** Find the first setter and its guard. Check whether its role slot starts as zero, then enumerate independent roots (A, D, P).
6. **Renounce.** After a hypothetical `_owner = 0`, re-evaluate every `onlyOwner` expression. If a fixed disjunct remains, label it cosmetic.
7. **Proxy.** Find `initialize`, its guard, first caller and `_authorizeUpgrade` predicate.
8. **Names and comments.** Strip comments and re-read. Treat error strings and function names as untrusted; S5's `Recipient is Gwei` checks the sender.
9. **Classic classes** (sources not attached): apply [B1–B4](../reference/taxonomy.md#classic-bait-classes-b1-b4) when those sources become available.

## 4. Dynamic test on a fork

Only after static triage, on a local fork with throw-away keys. State the block number.

| Probe | Confirms | Expected for a backdoored session |
|---|---|---|
| Fresh address: buy, then sell via router | T1/T2/T3 | Sell reverts, or receives 0 when `sellFee=100` |
| Fresh address: wallet-to-wallet `transfer` | Path asymmetry (T2) | Succeeds with full amount in S6–S9 |
| Same address sell before and after privileged `zap` / `blacklist` | T3 | Second sell reverts (S5, S8, S10, S13, S14) |
| Call `onlyOwner` function impersonating **A** after `renounceOwnership()` | T7/T8 | Succeeds; A also passes `_authorizeUpgrade` in S8/S9/S14 |
| Call `print` / `proof` / `viewBalance` from A or P | T4/T5 | Supply or balance changes without a cap; supply invariant breaks |
| Compare `totalSupply()` with sum of zero-address `Transfer` events | T5, S14 divergence | Divergence appears |
| Identify first `initialize` caller and proxy admin | T8 | First caller owns implementation state |

Stop conditions: do not broadcast transactions to a live chain; do not fund any address with real assets; do not attempt to exploit a live contract.

## 5. Reporting

A finding should contain:

1. **Target** — file, line range, compiler pragma, source hash and (if applicable) chain/block.
2. **Predicate** — the exact transfer or privileged predicate, written symbolically.
3. **Evidence** — scanner field and line, plus the fork observation with block number.
4. **Impact class** — one or more IDs from the [taxonomy](../reference/taxonomy.md), with severity and its assumptions.
5. **Limits** — what was not tested (no compile, no live fork, classic sources absent, purpose of address C unknown).

Template: *"At S6 L205–216, `transferFrom` computes `fee = amount*sellFee/100` with divisor 100; five setters permit `sellFee = 100` ([Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier)). On a local fork at block N, a wallet-to-wallet transfer delivered the full amount while a router sell delivered zero. Not tested: live deployment, bytecode match."*

Related: [risk indicators](risk-indicators.md), [liquidity lifecycle](liquidity-lifecycle.md), [control plane](../analysis/control-plane.md).
