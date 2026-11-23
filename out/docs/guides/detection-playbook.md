# Detection Playbook

A repeatable procedure for deciding whether a token or bait contract can trap a holder. It is ordered from cheapest to most expensive; stop as soon as a step produces a confirmed finding.

## 0. Ground rules

* Work on a **local fork** or testnet with throw-away keys. Never connect a funded wallet to an unreviewed contract or dApp.
* Treat every label (`non-honeypot`, `renounced`, `audited`, `safe`) as an unverified claim.
* A negative result is **time-indexed**: record the block number and the state you tested.

## 1. Provenance and bytecode

1. Obtain verified source *and* on-chain runtime bytecode. Recompile with the exact compiler version and settings from the explorer; the output must match byte-for-byte (ignoring the metadata hash).
2. Identify proxies: EIP-1967 slots, `UUPSUpgradeable`, `delegatecall`. Review **both** proxy admin and implementation, and ask who can call `upgradeTo`.
3. For old-compiler contracts ([classic catalog](../reference/classic-honeypots.md)) use the exact historical compiler; behaviour such as dropped empty strings is version-specific.

## 2. Static triage scanner

`tools/scan_indicators.py` flags the patterns documented in the [control-plane analysis](../analysis/control-plane.md). It reads `.sol` files, strips comments, and reports per file:

| Field | Meaning |
|---|---|
| `decimal_address_literals` | `address(<20+ digit integer>)` values, decoded to hex |
| `hex_address_literals` | `address(0x…)` values |
| `address_assembled_from_fragments` | `uint160(…) << 128 / 96 / 64 / 32` pattern |
| `modifiers_with_hardcoded_address` | modifiers whose body contains an address literal |
| `msgsender_ne_function_guards` | `require(msg.sender != f())` guards |
| `balance_overwrites` | balance assignments whose right side is not an add/subtract |
| `double_credit_helpers` | two consecutive credits of the same amount to the same account |
| `role_chain_setters` | presence of `setMember/setUser/setMod/setAdm/setUsdtPair` |
| `transfer_gating_requires` | allow-list / blacklist / `ensure` requires on transfer paths |
| `fee_cap_is_100_percent` | `Fee <= 100` caps |
| `has_renounceOwnership`, `upgradeable_uups` | structural flags |

Run:

```bash
python3 -I tools/scan_indicators.py contracts/            # human-readable
python3 -I tools/scan_indicators.py contracts/ --json     # for CI or diffing
```

Triage rule of thumb: **any** of the first four fields being non-empty, or `balance_overwrites > 0`, warrants a full manual read. The scanner is regex-based; it will miss obfuscation it does not model and will occasionally over-report. It never proves safety.

Result on this repository (verified by running the tool):

| Sessions | Indicator hits |
|---|---|
| 1–10, 13, 14 | decimal address literals (3, or 4 in S6–S9) and fragment-assembled address; hard-coded address inside a privileged modifier |
| 11, 12, 15 | none |

## 3. Manual review checklist by class

| Class | Questions |
|---|---|
| **Sell path** | In `transfer`, `transferFrom`, `_transfer`, `_beforeTokenTransfer`: which conditions can revert for an ordinary holder? Do `transfer` and `transferFrom` differ? |
| **Privileges** | Who can mint, burn, blacklist, pause, set fees, set pair/limits, upgrade? List *every* branch of every privileged modifier, including literals and negative guards. |
| **Role chains** | If setters require the *previous* role, trace until you reach an externally-owned account. Dormant ≠ safe. |
| **Fee ceilings** | Is there a hard cap below 100 %? `Fee <= 100` is not a cap. |
| **Supply** | Does $\sum$ balances equal `totalSupply`? Is any helper adding the same amount twice or assigning a balance? ([Math §4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect)) |
| **Renounce** | After `renounceOwnership()`, can any privileged function still be called by someone? |
| **Proxies** | Is `initialize` protected (`_disableInitializers`, constructor, atomic deploy+init)? Who can upgrade? |
| **Names** | Do `view`-sounding functions write state? Does each error string describe the check that fires? |
| **Arithmetic / types** | `var`, narrow loop counters, `unchecked` blocks, solidity < 0.8 wrap-around. |
| **External calls** | Addresses fixed at construction or stored in mutable state; `delegatecall`; reverts in "log" or "oracle" helpers. |

## 4. Dynamic test on a fork

The empirical test is the strongest evidence for sellability. Procedure:

1. Fork the chain at block $b$. Deploy or locate the token and its pair.
2. For at least **two fresh addresses**: buy a small amount through the router; approve; sell it back through the router.
3. Compute $\rho = q_{\text{out}}/q_{\text{in}}$ and compare with the pool-math expectation $\rho_0$ ([Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification)). Record reverts with their revert data.
4. Repeat after: (a) advancing time/blocks, (b) a transaction by every address the static review identified as privileged (use `vm.prank`/impersonation on the fork), (c) a holder balance well above the pool's per-trade depth.
5. Compare event-derived supply with `totalSupply()` ([Math §4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect)).

With Foundry this is a short test using `vm.createSelectFork`, `vm.prank` and the router's `swapExactETHForTokensSupportingFeeOnTransferTokens` / `swapExactTokensForETHSupportingFeeOnTransferTokens`. The test body is intentionally not bundled: it depends on the target chain, router and pair, and an unreviewed template is itself a risk.

## 5. Reporting

Record: chain and block; address(es); compiler and bytecode hash; each finding with file/line, the *capability* it grants (mint, freeze, drain, upgrade), a reproduction transaction on the fork, and the relevant equation. Severity follows reachability — a mint reachable by any address that is not provably controlled by holders is **Critical** regardless of whether it has been used.
