# Session 12 — Automatic Ownership-Renounce Meme Token

## Identification

| Field | Value |
|---|---|
| Session | 12 |
| Source file | `contracts/token/session-12-auto-ownership-renounce-meme-token.sol` |
| Root artifact | `automatic ownership renounce-normal-low gas fee-meme-token-non honeypot-code` |
| Solidity pragma | `^0.8.0` |
| Lines (incl. comments) | 90 |
| Structural family | Clean — minimal ERC-20 |
| Threat classes | — ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Informational** |
| Verdict | No hidden privilege found |

## Mechanism

- `onlyOwner` L19–22 requires `owner == msg.sender`, impossible after construction.
- `_transfer` L41–54 checks balance before `unchecked` subtract; addition cannot overflow because supply is fixed at $10^{24}$.
- `name`, `symbol`, `decimals`, `totalSupply` are storage variables (L5–8), not `constant`; no setters exist.
- No mint, burn, fee, list, proxy or hard-coded address in the file.

## Transfer predicate

$P \equiv \text{true}$ (subject only to balance and zero-address checks); no fee, list or privileged gate.

## Equations

—

## Detection signals

- `owner()` returns zero immediately after deployment.
- No mint/fee/list entry points; scanner reports no indicators.

## Hard-coded addresses

None found in source or scanner output.

## Evidence

Source lines read for this page: L4–30, L36–89. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
