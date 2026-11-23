# Session 2 - Honeypot Token (V1.2)

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-02-honeypot-v1-2.sol` |
| Original name | `honeypot-contract-V1.2` |
| Solidity | legacy |

## Summary

Iterated honeypot contract variant with updated transfer restriction logic.

## Risk Notes

- Unsellable token behavior for buyers.
- Privileged owner controls.

## Defensive Review

- Fork-test buys/sells from multiple addresses.
- Inspect modifiers and owner checks.

## Disclaimer

This artifact is documented for security research and defensive analysis only. Do not deploy or use it to deceive or harm users.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
