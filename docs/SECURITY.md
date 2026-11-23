# Security and Responsible Use

## Intended use

* Defensive security research and detection engineering
* Smart-contract auditing education
* Honeypot and hidden-privilege analysis in controlled environments

## Prohibited use

* Deploying any contract in this repository, or a derivative, to deceive users or take funds
* Presenting a contract with hidden privileges as safe, audited, "renounced" or "non-honeypot"
* Using the scanner's findings or the documented patterns to **evade** detection by other analysts or scanners
* Sending real funds to any contract described here

## Safe handling

1. Use a **local fork** (Anvil/Hardhat) or a testnet; never mainnet funds.
2. Use freshly generated throw-away keys; never import a wallet that holds real assets.
3. Static source review requires no wallet at all. Prefer it first.
4. Treat every label (`non-honeypot`, `renounced`, `audited`, `safe`, `V2`) as an unverified claim; see the [errata](analysis/errata.md).
5. Treat every privileged function as hostile until its reachability is established ([playbook §4](guides/detection-playbook.md#4-dynamic-test-on-a-fork)).
6. Do not execute the classic bait contracts against anything that holds value; they require historical 0.4.x semantics and their sources are not attached here ([classic catalog](reference/classic-honeypots.md)).
7. Impersonating a fixed address on a local fork is analysis. Doing anything equivalent on a live chain is out of scope.

## Evidence discipline

* Every claim in this handbook is tied to a source line, a scanner field or an exact arithmetic check. Reports are in [`reports/`](../reports/).
* `reports/numbers.txt` was produced with exact integer/rational arithmetic; no on-chain quantity was evaluated with floating point.
* Static reading found no compiler or runtime execution here. A "clean" verdict (S11, S12, S15) means no indicator was found, not that a deployed instance was audited.
* If a claim cannot be verified from the attached source, it is labelled unverified rather than inferred ([classic catalog](reference/classic-honeypots.md), [errata](analysis/errata.md#standing-limitations)).

## Reporting a finding

Follow [playbook §5](guides/detection-playbook.md#5-reporting): source line, observed predicate, reproduction on a local fork, and an explicit statement of what was *not* tested.
