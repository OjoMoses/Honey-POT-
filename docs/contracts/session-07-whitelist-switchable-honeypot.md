# Session 7 - Whitelist + Switchable Honeypot Mode

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-07-whitelist-switchable-honeypot.sol` |
| Original name | `whitelist-switch on&off honeypot mode-honeypot-scanner-detector-proof-token` |
| Solidity | legacy |

## Summary

Combines whitelist controls with switchable honeypot/trading mode.

## Risk Notes

- Multiple control planes for restricting sells.
- Owner can selectively enable exits.

## Defensive Review

- Audit all owner-only state variables affecting transfers.
- Test sells under different mode states.

## Disclaimer

This artifact is documented for security research and defensive analysis only. Do not deploy or use it to deceive or harm users.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
