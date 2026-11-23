# Threat Taxonomy

A compact classification of how a token or bait contract can lock in or extract value from a user. IDs are stable and referenced from the session pages.

| ID | Class | Definition | Representative | Primary equation |
|---|---|---|---|---|
| **T1** | Sell gate | Transfer predicate $P$ false for ordinary holders on the sell path | S1–S4 | [Math §3](math.md#3-sellability-predicate-and-honeypot-classification) |
| **T2** | Fee switch | Owner-settable sell tax with ceiling ≥ 100 % | S6, S7, S9 | [Math §2](math.md#2-fees-taxes-and-the-round-trip-multiplier) |
| **T3** | Selective freeze | Per-address blacklist applied to sellers | S5, S8, S10, S13, S14 | §3 |
| **T4** | Hidden mint | Reachable function increases supply without a cap | S5–S10, S13, S14 | [Math §5](math.md#5-dilution-and-pool-drain-from-hidden-minting) |
| **T5** | Balance overwrite / double credit | Assigns or double-adds a balance, breaking $\sum b = S$ | S1–S10, S13, S14 | [Math §4](math.md#4-supply-invariants-and-the-double-credit-defect) |
| **T6** | Latent role chain | Privileges reachable only after a multi-step setter sequence | S1–S10, S13, S14 | [Control plane §2](../analysis/control-plane.md#2-the-latent-role-chain) |
| **T7** | Cosmetic renounce | `renounceOwnership` exists but another path to the same privileges remains | S5–S10, S13, S14 | [Control plane §2](../analysis/control-plane.md#2-the-latent-role-chain) |
| **T8** | Upgrade takeover | Unprotected initializer or owner-controlled upgrade | S8, S9, S14 | n/a |
| **T9** | Obfuscation | Literals in decimal, addresses assembled from fragments, misleading names/strings | S1–S10, S13, S14 | [Control plane §1](../analysis/control-plane.md#1-four-techniques-in-order-of-how-often-they-hide-a-risk) |
| **B1** | Bait: arithmetic | Reward condition unsatisfiable by arithmetic or integer width | `01`, `07`, `07a`, `10` | [Math §6](math.md#6-classic-honeypot-arithmetic) |
| **B2** | Bait: storage | Storage-layout, shadowing or delegatecall corruption | `04`, `05`, `09` | §6.4 |
| **B3** | Bait: hidden state | State changed outside the visible source | `02`, `02a`, `06` | n/a |
| **B4** | Bait: presentation/toolchain | Whitespace, silent syntax, compiler behaviour | `03`, `08`, `11` | n/a |

## Severity model

Severity is assigned by **reachability × impact**, not by whether abuse has happened.

| Level | Condition |
|---|---|
| Critical | Unbounded mint, balance overwrite, or sell gate reachable by a party that is not a holder |
| High | Fee ceiling ≥ 100 %, blacklist of sellers, unprotected initializer |
| Medium | Misleading names that do not themselves grant a capability |
| Informational | Style, unused code, events not emitted |
