# Session 5 - Blacklist + Detector-Proof Honeypot

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-05-blacklist-detector-proof-honeypot.sol` |
| Original name | `honeypot-scanner-detector-proof-token` |
| Solidity | legacy |

## Summary

Variant advertised as blacklist-based and scanner/detector-resistant; uses conditional transfer restrictions.

## Risk Notes

- Blacklist/conditional logic can block sells.
- Scanner evasion claims should be treated as a red flag.

## Defensive Review

- Do not rely on scanner labels alone.
- Manual review and fork simulation required.

## Disclaimer

This artifact is documented for security research and defensive analysis only. Do not deploy or use it to deceive or harm users.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
