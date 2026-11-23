# Security and Responsible Use

## Intended use

* Defensive security research and detection engineering
* Smart-contract auditing education
* Honeypot and hidden-privilege analysis in controlled environments

## Prohibited use

* Deploying any contract here, or a derivative, to deceive users or take funds
* Presenting a contract with hidden privileges as safe, audited, "renounced" or "non-honeypot"
* Using the scanner's findings, or the documented patterns, to evade detection by other analysts or scanners

## Safe handling

1. Use a **local fork** (Anvil/Hardhat) or a testnet; never mainnet funds.
2. Use freshly generated keys; never import a wallet that holds real assets.
3. Do not click through dApps or approve tokens from unknown contracts; analysing source does not require a wallet.
4. Treat every privileged function as hostile until its **reachability** is established ([playbook](guides/detection-playbook.md)).
5. Do not execute classic bait contracts (`Honeypots-on-Blockchain`) against anything that holds value; they require Solidity 0.4.x semantics.

## Reporting a finding about a live token

Record chain, address, block, compiler/bytecode hash, the capability (mint, freeze, drain, upgrade), a reproduction on a fork, and the relevant equation. Share with the affected project's security contact or a recognised disclosure channel; do not publish exploit steps for contracts that still hold user funds.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
