# Smart Contract Honeypot Research Repository

A documentation-oriented repository containing smart-contract project artifacts, organized code files, and reference documentation for defensive security research, auditing education, and token-contract analysis.

> **Responsible use:** This repository includes honeypot-pattern examples. Use the contents only for legitimate research, auditing, and defensive analysis in controlled environments. Do not use these materials to deploy scams, deceive users, or cause financial harm.

## Repository Structure

```text
Honey-POT-/
├── README.md
├── contracts/                  # Organized contract artifacts (.sol)
│   ├── honeypot/               # Honeypot-pattern contracts (Session 1-9)
│   └── token/                  # Other token contract examples (Session 10-15)
├── docs/                       # Documentation
│   ├── overview.md             # Documentation overview and session index
│   ├── SECURITY.md             # Responsible-use and safety notes
│   ├── contracts/              # Per-contract session reference docs
│   └── guides/                 # Neutral research/analysis guides
├── Session 1 - ... .md         # Sequenced tutorial/session notes (root)
├── ...                         # Original contract/source artifact files (root)
└── beginner-guide, ...         # Original guide/reference files (root)
```

## Root Contents

### Upgraded Code Sessions (Syntax/Code Files)

| Session | File |
|---|---|
| Session 1 | [Session 1 - Upgraded V2 Blacklist Honeypot Detector Proof.sol](Session%201%20-%20Upgraded%20V2%20Blacklist%20Honeypot%20Detector%20Proof.sol) |
| Session 2 | [Session 2 - Upgraded V2 Whitelist Switch On-Off Honeypot Mode.sol](Session%202%20-%20Upgraded%20V2%20Whitelist%20Switch%20On-Off%20Honeypot%20Mode.sol) |
| Session 3 | [Session 3 - Upgraded V2 Automatic Ownership Renounce Meme Token.sol](Session%203%20-%20Upgraded%20V2%20Automatic%20Ownership%20Renounce%20Meme%20Token.sol) |
| Session 4 | [Session 4 - Upgraded V2 Unlimited Supply Printing Meme Token.sol](Session%204%20-%20Upgraded%20V2%20Unlimited%20Supply%20Printing%20Meme%20Token.sol) |

### Original Artifact Files (Root)

The root also retains the original source/reference files, including contract artifacts and guides:

- `honeypot-smart-contract`, `honeypot-smart-contract-0.8.19`, `honeypot-contract-V1.2`
- `whitelist-antibot-smart-contract`
- `honeypot-scanner-detector-proof-token`
- `switch on&off honeypot mode-honeypot-scanner-detector-proof-token`
- `whitelist-switch on&off honeypot mode-honeypot-scanner-detector-proof-token`
- `normal-meme-pepe-token-non honeypot-code`
- `ownership renounce-normal-meme-token-non honeypot-code`
- `automatic ownership renounce-normal-low gas fee-meme-token-non honeypot-code`
- `unlimited supply printing-normal-meme-token-non honeypot-code`

## Documentation

- [Overview](docs/overview.md) - Documentation structure and contract session index
- [Security & Responsible Use](docs/SECURITY.md) - Safe handling and intended use

### Guides

- [Getting Started (Research Context)](docs/guides/getting-started.md)
- [Liquidity Lifecycle Notes](docs/guides/liquidity-lifecycle.md)
- [Risk Indicators and Abuse Patterns](docs/guides/risk-indicators.md)

### Contract Session Reference (`docs/contracts/`)

| Session | Reference | Artifact |
|---|---|---|
| Session 1 | [Honeypot Token (V1)](docs/contracts/session-01-honeypot-v1.md) | `contracts/honeypot/session-01-honeypot-v1.sol` |
| Session 2 | [Honeypot Token (V1.2)](docs/contracts/session-02-honeypot-v1-2.md) | `contracts/honeypot/session-02-honeypot-v1-2.sol` |
| Session 3 | [Honeypot Token (V1, Solidity 0.8.19)](docs/contracts/session-03-honeypot-v1-solidity-0.8.19.md) | `contracts/honeypot/session-03-honeypot-v1-solidity-0.8.19.sol` |
| Session 4 | [Whitelist + Anti-Bot Honeypot](docs/contracts/session-04-whitelist-antibot-honeypot.md) | `contracts/honeypot/session-04-whitelist-antibot-honeypot.sol` |
| Session 5 | [Blacklist + Detector-Proof Honeypot](docs/contracts/session-05-blacklist-detector-proof-honeypot.md) | `contracts/honeypot/session-05-blacklist-detector-proof-honeypot.sol` |
| Session 6 | [Switchable Honeypot Mode](docs/contracts/session-06-switchable-honeypot-mode.md) | `contracts/honeypot/session-06-switchable-honeypot-mode.sol` |
| Session 7 | [Whitelist + Switchable Honeypot Mode](docs/contracts/session-07-whitelist-switchable-honeypot.md) | `contracts/honeypot/session-07-whitelist-switchable-honeypot.sol` |
| Session 8 | [Upgraded V2 Blacklist + Detector-Proof Honeypot](docs/contracts/session-08-v2-blacklist-detector-proof.md) | `contracts/honeypot/session-08-v2-blacklist-detector-proof.sol` |
| Session 9 | [Upgraded V2 Whitelist + Switchable Honeypot](docs/contracts/session-09-v2-whitelist-switchable.md) | `contracts/honeypot/session-09-v2-whitelist-switchable.sol` |
| Session 10 | [Normal Meme Token (Non-Honeypot Example)](docs/contracts/session-10-normal-meme-token.md) | `contracts/token/session-10-normal-meme-token.sol` |
| Session 11 | [Ownership-Renounce Meme Token](docs/contracts/session-11-ownership-renounce-meme-token.md) | `contracts/token/session-11-ownership-renounce-meme-token.sol` |
| Session 12 | [Automatic Ownership-Renounce Meme Token](docs/contracts/session-12-auto-ownership-renounce-meme-token.md) | `contracts/token/session-12-auto-ownership-renounce-meme-token.sol` |
| Session 13 | [Unlimited Supply Printing Meme Token](docs/contracts/session-13-unlimited-supply-meme-token.md) | `contracts/token/session-13-unlimited-supply-meme-token.sol` |
| Session 14 | [Upgraded V2 Unlimited Supply Printing Meme Token](docs/contracts/session-14-v2-unlimited-supply-meme-token.md) | `contracts/token/session-14-v2-unlimited-supply-meme-token.sol` |
| Session 15 | [Upgraded V2 Automatic Ownership-Renounce Meme Token](docs/contracts/session-15-v2-auto-ownership-renounce-meme-token.md) | `contracts/token/session-15-v2-auto-ownership-renounce-meme-token.sol` |

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
