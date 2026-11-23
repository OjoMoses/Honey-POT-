# Session 15 — Upgraded V2 Automatic Ownership-Renounce Meme Token

## Identification

| Field | Value |
|---|---|
| Session | 15 |
| Source file | `contracts/token/session-15-v2-auto-ownership-renounce-meme-token.sol` |
| Root artifact | `Session 3 - Upgraded V2 Automatic Ownership Renounce Meme Token.sol` |
| Solidity pragma | `^0.8.0` |
| Lines (incl. comments) | 90 |
| Structural family | Clean — minimal ERC-20 (constants) |
| Threat classes | — ([taxonomy](../reference/taxonomy.md)) |
| Severity | **Informational** |
| Verdict | No hidden privilege found |

## Mechanism

- Constructor L24–30 assigns the fixed supply to the deployer and calls `renounceOwnership()` (L29).
- `onlyOwner` L19–22 requires `owner == msg.sender`; `renounceOwnership` L86–89 sets `owner = 0`.
- `_transfer` L41–54 checks balance before `unchecked` arithmetic; supply is compile-time constant $10^{18}\times10^{6}$.
- No hard-coded addresses, no role chain, no UUPS/initialize; scanner reports no indicators.

## Transfer predicate

$P \equiv \text{true}$ (subject only to balance and zero-address checks); no fee, list or privileged gate.

## Equations

—

## Detection signals

- Confirm absence of proxy/initializer bytecode on any deployed copy; the `V2` name alone proves nothing.
- Reader functions return constants, so storage-read gas differs from Session 12.

## Hard-coded addresses

None found in source or scanner output.

## Evidence

Source lines read for this page: L4–30, L36–89. Line numbers refer to the `.sol` file in this repository. Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).

## Review guidance

Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. See the [detection playbook](../guides/detection-playbook.md).

> Defensive analysis only. Do not deploy this code or present it as safe.
