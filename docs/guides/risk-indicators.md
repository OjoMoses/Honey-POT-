# Risk Indicators

Concrete, testable red flags. Each row says what to look for, why it matters and how to confirm it. Severity follows the [taxonomy](../reference/taxonomy.md#severity-model).

## Code-level indicators

| Indicator | Why it matters | Confirm with | Severity |
|---|---|---|---|
| `address(<very large decimal>)` in a `require` | Hides a privileged address from hex search | Scanner `decimal_address_literals`; decode with exact integer formatting | Critical |
| `uint160(…) << 128 \| 96 \| 64 \| 32` in a `pure` function returning an address | Address assembled at runtime | Scanner `address_assembled_from_fragments` | Critical |
| `onlyOwner` that also accepts a literal address | Renounce is cosmetic | Read the modifier; call a gated function after `owner = 0` on a fork | Critical |
| `balances[x] = v` (assign, not add) | Overwrites balances including the pair's | Scanner `balance_overwrites` | Critical |
| Two consecutive credits of the same amount | $\sum b \ne$ `totalSupply` | Scanner `double_credit_helpers`; compare supplies | Critical |
| `setMember → setUser → setMod → setAdm` chain | Latent privilege requiring a seeder | Scanner `role_chain_edges`; check zero initial slots | Critical |
| Fee setter with `<= 100` and divisor `100` | 100 % fee is reachable | Five hits each in S6, S7, S9 | Critical |
| `transfer` and `transferFrom` differ in fee or gates | Sell path can be trapped while wallet transfers look fine | Read both; see [Math §2](../reference/math.md#2-fees-taxes-and-the-round-trip-multiplier) | Critical |
| Public `initialize` + no `_disableInitializers` in UUPS | First caller wins owner and supply | Scanner `uups`, `initialize`; inspect the first initializer tx | Critical |
| `_authorizeUpgrade` gated by the A-accepting modifier | Upgrade key survives renounce | Read L486 (S8), L80 (S9), L737 (S14) | Critical |
| Blacklist checked only on sender, error says `Recipient` | Censorship that a fresh-address test misses | S5 L637; S8 L637 | High |
| `sell()` ignores `isFeeExempt` | Exemption is not a safety guarantee | S7 L368–382, S9 L376–390 | High |
| View-sounding function that writes | Reviewers and tooling may skip it | `viewBalance`, `approval`, `_balanceView` | High |
| Fake keccak / OpenZeppelin comments | Obfuscation around live address literals | Invalid hex characters such as `j`, `t` in S1/S4 | Medium |
| File name or label claims `non honeypot` / `safe` | Unverified claim, contradicted by source | S10, S13; see [errata](../analysis/errata.md#substantive-corrections) | Informational |

## Negative indicators are not proof

S11, S12 and S15 have no scanner hits and no privileged path in source. That supports a "no indicator found" conclusion for *these files*, not an audit of any deployed instance. Bytecode match, compiler settings and proxy state remain outside this repository's evidence.

## Triage order

1. Run the [scanner](detection-playbook.md#2-static-triage-scanner) and read its line references, not just counts.
2. Expand modifiers into predicates ([control plane](../analysis/control-plane.md#13-negative-guards-and-exclusion-lists)).
3. Decode all addresses and compare with the [IOC table](../analysis/control-plane.md#2-ioc-address-table).
4. Only then consider a [local fork test](detection-playbook.md#4-dynamic-test-on-a-fork).

Scope: analysis and detection only. Do not use these indicators to design an evasion strategy.
