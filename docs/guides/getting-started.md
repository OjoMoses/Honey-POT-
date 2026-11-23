# Getting Started

A one-page orientation for someone about to review these contracts. Analysis and detection only.

## What you need

| Item | Why |
|---|---|
| Python 3.8+ | Run `tools/scan_indicators.py`, `tools/verify_numbers.py`, `tools/check_links.py` — all stdlib-only |
| Foundry (`forge`, `anvil`, `cast`) or Hardhat | Local fork, impersonation, address/hex conversion |
| Solidity compilers 0.4.26, 0.5.16, 0.8.x | Match each file's pragma if you compile; the classic baits need exact historical versions |
| Archive-node RPC (optional) | Fork a real chain to inspect a deployed token |

No wallet is required for static review. Never connect one that holds real assets.

## First hour

1. Read the [README findings](../../README.md#key-findings) and the [taxonomy](../reference/taxonomy.md).
2. Run the scanner on `contracts/` and compare with the [expected fields and counts](detection-playbook.md#2-static-triage-scanner).
3. Open [Session 1](../contracts/session-01-honeypot-v1.md) and [Session 12](../contracts/session-12-auto-ownership-renounce-meme-token.md) side by side — the most hostile and the cleanest — and list every difference in the privileged surface.
4. Read the [control plane](../analysis/control-plane.md) and decode the five recurring addresses yourself with exact integer arithmetic.
5. Reproduce one number from [Math §5](../reference/math.md#5-dilution-and-pool-drain-from-hidden-minting) using `python3 -I tools/verify_numbers.py`.

## What the corpus is

* `contracts/honeypot/` — S1–S9: allow-list gates, permanent anti-bot locks, blacklists and fee switches.
* `contracts/token/` — S10–S15: OZ-shaped tokens, UUPS variants and two clean minimal tokens.
* Twelve of fifteen sessions share a hidden control plane; three (S11, S12, S15) show no indicator. The claim "non honeypot" in S10/S13 file names is false ([errata](../analysis/errata.md#substantive-corrections)).
* The 14 [classic baits](../reference/classic-honeypots.md) are **not** in the archive; their entries are unverified pre-existing claims.

## Conventions used here

* Session numbers S1–S15 follow `contracts/`. The root-level `Session 1…4 - Upgraded V2 …` files use a different numbering; see the [mapping](../analysis/errata.md#naming-collisions).
* Line numbers include comments and blank lines and refer to the extracted LF copies.
* Fixed addresses are labelled **A**, **B**, **C**, **D**, **P**; see the [IOC table](../analysis/control-plane.md#2-ioc-address-table).
* Every quantitative claim is reproduced in [`reports/numbers.txt`](../../reports/numbers.txt).

## Next

Follow the [detection playbook](detection-playbook.md) from §1, or browse [risk indicators](risk-indicators.md) for a quick checklist. Ground rules are in [SECURITY](../SECURITY.md).
