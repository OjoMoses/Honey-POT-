# Session 1 - Honeypot Token (V1)

| Field | Value |
|---|---|
| Category | honeypot |
| Source file | `contracts/honeypot/session-01-honeypot-v1.sol` |
| Original name | `honeypot-smart-contract` |
| Solidity | ^0.8.x/legacy style |

## Summary

Baseline ERC-20/BEP-20 honeypot contract that restricts sell transfers for non-privileged addresses.

## Risk Notes

- Buyers may be unable to sell.
- Owner-privileged transfer logic.
- High risk of fund loss for unsuspecting users.

## Defensive Review

- Simulate buy and sell before interacting.
- Review transfer/sell restrictions and owner-only branches.
- Check ownership and privilege functions on-chain.

## Disclaimer

This artifact is documented for security research and defensive analysis only. Do not deploy or use it to deceive or harm users.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
