# Session 4 - Whitelist + Anti-Bot Honeypot

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-04-whitelist-antibot-honeypot.sol` |
| Original name | `whitelist-antibot-smart-contract` |
| Solidity | legacy |

## Summary

Honeypot variant combining whitelist-based transfer permissions with anti-bot/front-running framing.

## Risk Notes

- Whitelist can be used to allow only selected sellers.
- Owner can gate liquidity exits.

## Defensive Review

- Check whitelist management functions and default sell permissions.
- Verify whether non-whitelisted addresses can sell.

## Disclaimer

This artifact is documented for security research and defensive analysis only. Do not deploy or use it to deceive or harm users.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
