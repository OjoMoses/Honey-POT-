# Session 11 — Ownership-Renounce Meme Token

## Identification

| Field | Value |
|---|---|
| Session | 11 |
| Source file | `contracts/token/session-11-ownership-renounce-meme-token.sol` |
| Root artifact | `ownership renounce-normal-meme-token-non honeypot-code` |
| Solidity pragma | `0.5.16` |
| Lines (incl. comments) | 588 |
| Structural family | Clean — plain BEP-20 |
| Threat classes | — ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Informational** |
| Verdict | No hidden privilege found |

## Mechanism

- `_transfer` L512–519 checks zero addresses and balance only; `transfer`/`transferFrom` L411–451.
- `_mint` L530–536, `_burn` L549–555 and `_burnFrom` L584–587 are internal and have no public callers.
- An orphan doc comment at L489–496 describes a `mint` function that does not exist in the code — treated as an unverified claim, not behaviour.
- Scanner reports no IOCs, no role chain, no fee caps and no UUPS/initialize.

## Transfer predicate

$P \equiv \text{true}$ (subject only to balance and zero-address checks); no fee, list or privileged gate.

## Equations

—

## Detection signals

- Verify deployed bytecode matches this source before drawing conclusions about a live token.
- Confirm `owner()` is zero if the renounce claim matters.

## Hard-coded addresses

None found in source or scanner output.

## Evidence

Source lines read for this page: L280–359, L411–451, L512–587. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
