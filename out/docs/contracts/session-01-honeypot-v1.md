# Session 1 — Honeypot Token (V1)

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-01-honeypot-v1.sol` |
| Original root file | `honeypot-smart-contract` |
| Solidity | `^0.4.26` |
| Length | 284 lines |
| Structural family | 1 (allow-list sell gate) |
| Threat classes | T1 T4 T5 T6 T9 ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Critical** |

## Summary

ERC-20-style token whose `transfer` is unrestricted but whose `transferFrom` requires `allow[_from] == true`. Router sells use `transferFrom`, so only allow-listed addresses can sell.

## How it works

- `transfer(to, v)` has no sender restriction, so wallet-to-wallet transfers and pool-to-buyer deliveries succeed.
- `transferFrom` additionally requires `allow[_from]`; the constructor allow-lists only the deployer. Every ordinary holder's sale through a DEX reverts.
- `onlyOwner` checks a hard-coded address (**A**), not the stored `owner`; the deployer holds no owner power through this modifier.
- `mint(miner, v)` *assigns* `balances[miner] = v`; `approveAndCall` (`_adm`) and `adjust` (**P**) overwrite balances the same way.
- `transferTo` and `viewBalance` credit the target twice without changing `totalSupply`.

## Transfer predicate

$P(h)=\mathbb{1}[\texttt{allow}[h]]$ in `transferFrom`; `transfer` unrestricted.

## Equations

[Math §3](../reference/math.md#3-sellability-predicate-and-honeypot-classification), [§4](../reference/math.md#4-supply-invariants-and-the-double-credit-defect)

## Detection signals

- Router sell reverts from a fresh address while a plain `transfer` works.
- `allow` mapping with only the deployer set.
- Decimal address literals and `publics()` fragment assembly (scanner).

## Hard-coded addresses

0x1f490e99…0e7a (**A**), 0x78322d0c…e051 (**B**), 0x0320e7dc…0e7a (**C**), and the runtime-assembled 0x7addad09…c336 (**P**). Full table: [control-plane analysis](../analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).

## Review guidance

Reproduce findings on a local fork only. Use the [detection playbook](../guides/detection-playbook.md); do not trust the file name, labels or comments as evidence of behaviour.

> Documented for defensive analysis and education. Do not deploy this code or present it as safe.
