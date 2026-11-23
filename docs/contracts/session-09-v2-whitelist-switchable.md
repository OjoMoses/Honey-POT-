# Session 9 - Upgraded V2 Whitelist + Switchable Honeypot

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-09-v2-whitelist-switchable.sol` |
| Original name | `Upgraded V2-whitelist-switch on&off honeypot mode-honeypot-scanner-detector-proof-token` |
| Solidity | legacy |

## Summary

V2 variant combining whitelist and mode switching.

## Risk Notes

- Owner can change sellability conditions.
- Selective exit control.

## Defensive Review

- Check mode/whitelist state transitions and privileged functions.

## Disclaimer

This artifact is documented for security research and defensive analysis only. Do not deploy or use it to deceive or harm users.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
