# Session 11 - Ownership-Renounce Meme Token

| Field | Value |
|---|---|
| Category | token |
| Source file | `contracts/token/session-11-ownership-renounce-meme-token.sol` |
| Original name | `ownership renounce-normal-meme-token-non honeypot-code` |
| Solidity | legacy |

## Summary

Meme-token example with ownership renounce capability.

## Risk Notes

- Renounce may be incomplete or bypassable depending on implementation.
- Other privileged roles may remain.

## Defensive Review

- Verify renounce implementation and all privileged roles.

## Disclaimer

This artifact is documented for security research and defensive analysis only. Do not deploy or use it to deceive or harm users.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
