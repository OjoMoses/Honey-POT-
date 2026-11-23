# Session 6 - Switchable Honeypot Mode

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-06-switchable-honeypot-mode.sol` |
| Original name | `switch on&off honeypot mode-honeypot-scanner-detector-proof-token` |
| Solidity | legacy |

## Summary

Variant with owner-controlled mode switching that can alter trading/sell behavior.

## Risk Notes

- Behavior can change after purchase.
- Owner can enable restrictive mode.

## Defensive Review

- Inspect mode flags and owner setters.
- Monitor for post-launch configuration changes.

## Disclaimer

This artifact is documented for security research and defensive analysis only. Do not deploy or use it to deceive or harm users.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
