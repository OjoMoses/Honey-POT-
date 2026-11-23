# Session 3 - Honeypot Token (V1, Solidity 0.8.19)

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-03-honeypot-v1-solidity-0.8.19.sol` |
| Original name | `honeypot-smart-contract-0.8.19` |
| Solidity | 0.8.19 |

## Summary

Honeypot variant targeting Solidity 0.8.19 compiler behavior.

## Risk Notes

- Sell restrictions hidden in transfer logic.
- Owner-controlled behavior.

## Defensive Review

- Static analysis of transfer path.
- Test sell path on fork/simulator.

## Disclaimer

This artifact is documented for security research and defensive analysis only. Do not deploy or use it to deceive or harm users.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
