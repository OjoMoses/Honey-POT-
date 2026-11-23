# Getting Started (Research Context)

This document provides a high-level, neutral overview for understanding the repository as a set of smart-contract artifacts for security research and analysis.

## Purpose

- Identify contract types present in this repository.
- Understand common risk areas in ERC-20/BEP-20 token contracts.
- Support defensive review, auditing, and detection research.

## Before Reviewing Contracts

- **Environment**: Use a local/forked test environment; do not test unknown contracts against mainnet funds.
- **Wallet safety**: Use isolated wallets and test networks.
- **Assumptions**: Treat all claims in code comments or file names as unverified until reviewed.

## Review Checklist

- Read transfer/sell paths and owner-only modifiers.
- Check mint/burn, blacklist/whitelist, fee, and mode-switch functions.
- Verify ownership renounce behavior actually removes privileges.
- Simulate buy/sell/liquidity flows on a fork.
- Record findings with transaction traces and code references.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
