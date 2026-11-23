# Threat Taxonomy

Stable class IDs used by the session pages and the [detection playbook](../guides/detection-playbook.md). A session can carry several IDs. "Representative" cites source in this repository; classic bait classes (B1–B4) are pre-existing claims whose sources are **not attached**.

## Token classes T1–T9

| ID | Class | Definition | Representative | Evidence |
|---|---|---|---|---|
| **T1** | Sell gate | Transfer predicate false for ordinary holders on the router's `transferFrom` sell path | S1–S4 | S1 L176 `allow[_from]`; S4 L557 `condition()` |
| **T2** | Fee switch | Owner-settable sell tax with ceiling ≥ 100 % and asymmetric fee path | S6, S7, S9 | five `<= 100` caps per file; divisor 100 |
| **T3** | Selective freeze | Writable per-address blacklist applied to senders (or both parties) | S5, S8, S10, S13, S14 | S5 L637; S10 L778 |
| **T4** | Hidden mint | Reachable function increases supply without a cap | S5–S10, S13, S14 | S13 L823–826 `print` |
| **T5** | Balance overwrite / double credit | Assigns a balance or credits twice without raising supply, breaking $\sum b=S$ | S1–S10, S13, S14 | S1 L103/L106; [Math §4](math.md#4-supply-invariants-and-the-double-credit-defect) |
| **T6** | Latent role chain | Privileges reach only after a sequence of setters; all role slots zero at deployment | S1–S10, S13, S14 | B → `_usdtPair`/`_mbr` → `_user` → `_mod` → `_adm` |
| **T7** | Cosmetic renounce | `renounceOwnership()` zeroes stored owner but a fixed address still passes `onlyOwner` | S5–S10, S13, S14 | S5 L331–334 + L314–322 |
| **T8** | Proxy / initializer takeover | UUPS implementation with public first-caller-wins `initialize`; no `_disableInitializers` | S8, S9, S14 | S8 L306–320, L486; S9 L66–78, L80 |
| **T9** | Obfuscation | Decimal/fragment addresses, fake keccak comments, view-sounding writers, misleading error strings | S1–S10, S13, S14 | S1 L22, L209; S4 L407; S5 L637 |

## Classic bait classes B1-B4

Sources not attached; see the [classic catalog](classic-honeypots.md) and the standing limitation in [Math §6](math.md#6-classic-honeypot-arithmetic).

| ID | Class | Definition | Entries |
|---|---|---|---|
| **B1** | Arithmetic / type bait | Unsatisfiable condition, integer wrap or series bound | 01, 07, 07a, 10 |
| **B2** | Hidden or external state | Guard flipped by a contract-to-contract call, mutable answer, reverting logger | 02, 02a, 06 |
| **B3** | Storage / presentation | Shadowed variables, storage pointer overwrite, off-screen code, `delegatecall` | 03, 04, 05, 09 |
| **B4** | Syntax / toolchain | Missing call parentheses, compiler-version-dependent argument handling | 08, 11 |

## Severity model

Severity is a property of the *pattern as written*, not of any deployed token or observed loss. It assumes the fixed addresses are real EOAs not controlled by holders (unverifiable from source).

| Severity | Rubric | Sessions |
|---|---|---|
| **Critical** | Uncapped mint or balance overwrite **plus** hidden privilege that survives renounce, or a permanent sell lock, or UUPS upgrade key held by a fixed address. Holder funds can be taken or made unsellable without consent. | S1–S10, S13, S14 |
| **High** | Strong extraction primitive with a meaningful precondition (e.g. a cap that must be raised first, or a list that must be populated). Not used as a final verdict here; classic B1/B2 entries carry it as a pattern rating. | classic 01, 02, 02a, 04, 05, 06, 07, 07a, 09, 11 |
| **Medium** | Deception that hides a restriction but requires an additional actor or block-height condition; or a code-shape defect that does not by itself move value. | classic 03, 08, 10 |
| **Informational / Low** | No privileged path, no hidden address and no reachable state-changing surprise found in source or scanner output. Fixed supply, real renounce. | S11, S12, S15 |

Two rules keep the model honest:

1. **Label ≠ severity.** File names containing `non honeypot` (S10, S13) and `Upgraded V2` (S8, S9, S14, S15) carry no evidential weight.
2. **Clean ≠ audited.** S11, S12 and S15 are clean *relative to this scanner and this reading*. Deployed bytecode, compiler settings and proxy state remain outside this repository's evidence.

## Class → review step

| Class | Cheapest confirming check |
|---|---|
| T1 | Fresh address: `transfer` succeeds, router `transferFrom` sell reverts |
| T2 | Compare `transfer` and `transferFrom` amounts; read every fee-cap `require` |
| T3 | Compare sell before/after a privileged `zap`/`blacklist` call on a fork |
| T4 | Search for uncapped `+= amount` on supply and balance; check `print`/`proof`/`scale` guards |
| T5 | Compare $\sum b$ with reported supply; count zero-address `Transfer` events per helper |
| T6 | Decode the decimal seeder address; check whether role slots are zero at deployment |
| T7 | After `renounceOwnership()`, call an `onlyOwner` function from the stored A address on a fork |
| T8 | Identify the first `initialize` caller and the proxy admin; check `_authorizeUpgrade` |
| T9 | Strip comments and re-read; treat view-sounding names and error strings as untrusted |

Full procedure: [detection playbook](../guides/detection-playbook.md), indicators: [risk indicators](../guides/risk-indicators.md).
