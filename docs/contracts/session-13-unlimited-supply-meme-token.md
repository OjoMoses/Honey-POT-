# Session 13 - Unlimited Supply Printing Meme Token

| Field | Value |
|---|---|
| Category | token |
| Source file | `contracts/token/session-13-unlimited-supply-meme-token.sol` |
| Original name | `unlimited supply printing-normal-meme-token-non honeypot-code` |
| Solidity | legacy |

## Summary

Meme-token example with unlimited/minting supply capability.

## Risk Notes

- Unbounded minting can dilute holders.
- Mint authority is a centralization risk.

## Defensive Review

- Identify mint functions and access control.
- Check max supply/inflation constraints.

## Disclaimer

This artifact is documented for security research and defensive analysis only. Do not deploy or use it to deceive or harm users.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
