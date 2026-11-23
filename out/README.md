# Smart-Contract Honeypot Research Handbook

Defensive documentation for two collections of Solidity contracts:

* **Honey-POT** — 15 token contracts ("sessions") in `contracts/honeypot` and `contracts/token`, many of which hide privileged control behind obfuscated addresses.
* **Honeypots-on-Blockchain** — 14 classic Ethereum bait contracts (`01_…` – `11_…`) used for teaching how honeypots deceive would-be takers.

> **Responsible use.** These materials exist to help people **recognise, analyse and detect** honeypot and hidden-privilege tokens. Do not deploy, adapt or market any contract here as a safe investment, and do not use anything to evade scanners. Analyse on a local fork with throw-away keys. See [SECURITY](docs/SECURITY.md).

## Key findings

1. **12 of the 15 token sessions carry a hidden control plane**: Sessions 1–10, 13 and 14 accept hard-coded addresses (written as decimal integers or assembled from fragments) in privileged paths, expose a latent four-step role chain, and include uncapped mint, balance-overwrite and double-credit helpers. Only Sessions 11, 12 and 15 are clean.
2. **Files labelled "normal" or "non-honeypot" are not safe.** Sessions 10, 13 and 14 keep the same backdoor; "renounced" ownership in Sessions 5–10, 13 and 14 is cosmetic because `onlyOwner` also accepts a hard-coded address.
3. **Any reachable uncapped mint is equivalent to the right to drain the pool.** With reserves $x$ (token) and $y$ (quote), minting $m$ tokens and selling removes $\frac{\gamma m}{x+\gamma m}$ of $y$, which tends to 1 ([Math §5](docs/reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)).
4. **Single fresh-address sell tests are insufficient.** Sell gates keyed on holder identity, owner-set state or the call path (`transfer` vs `transferFrom`) pass such tests ([Playbook §4](docs/guides/detection-playbook.md#4-dynamic-test-on-a-fork)).
5. **The classic honeypots are mostly arithmetic and compiler semantics** — integer width, shadowing, uninitialised storage pointers, delegatecall — and each has a closed-form reason it can never pay out ([Catalog](docs/reference/classic-honeypots.md)).

## Documentation map

| Need | Go to |
|---|---|
| What is here and how to read it | [Overview](docs/overview.md) |
| Equations with worked, checked examples | [Mathematical reference](docs/reference/math.md) |
| How the hidden privileges are encoded; IOC addresses | [Control-plane analysis](docs/analysis/control-plane.md) |
| Classification of threat types and severity | [Taxonomy](docs/reference/taxonomy.md) |
| One page per token session (15) | [`docs/contracts/`](docs/contracts/) — index below |
| The 14 classic bait contracts | [Classic honeypot catalog](docs/reference/classic-honeypots.md) |
| Step-by-step review procedure and scanner | [Detection playbook](docs/guides/detection-playbook.md) |
| Practical orientation, liquidity, red flags | [Getting started](docs/guides/getting-started.md), [Liquidity lifecycle](docs/guides/liquidity-lifecycle.md), [Risk indicators](docs/guides/risk-indicators.md) |
| What changed from earlier docs | [Errata](docs/analysis/errata.md) |
| Terms and references | [Glossary](docs/reference/glossary.md) |

## Token session index (verified against source)

| # | Session | Solidity | Family | Verdict | Page |
|---|---|---|---|---|---|
| 1 | Honeypot Token V1 | ^0.4.26 | Allow-list sell gate | **Critical** | [S1](docs/contracts/session-01-honeypot-v1.md) |
| 2 | Honeypot Token V1.2 | ^0.4.26 | Allow-list sell gate | **Critical** | [S2](docs/contracts/session-02-honeypot-v1-2.md) |
| 3 | Honeypot Token V1 (0.8.19) | ^0.8.19 | Allow-list sell gate | **Critical** | [S3](docs/contracts/session-03-honeypot-v1-solidity-0.8.19.md) |
| 4 | Whitelist + Anti-Bot | — | Anti-bot condition (never satisfiable) | **Critical** | [S4](docs/contracts/session-04-whitelist-antibot-honeypot.md) |
| 5 | Blacklist + Detector-Proof | 0.5.16 | Seller blacklist | **Critical** | [S5](docs/contracts/session-05-blacklist-detector-proof-honeypot.md) |
| 6 | Switchable Honeypot Mode | ^0.8.0 | Fee switch (to 100 %) | **Critical** | [S6](docs/contracts/session-06-switchable-honeypot-mode.md) |
| 7 | Whitelist + Switchable | ^0.8.0 | Fee switch + exempt list | **Critical** | [S7](docs/contracts/session-07-whitelist-switchable-honeypot.md) |
| 8 | V2 Blacklist + Detector-Proof | ^0.8.24 | Seller blacklist, UUPS | **Critical** | [S8](docs/contracts/session-08-v2-blacklist-detector-proof.md) |
| 9 | V2 Whitelist + Switchable | ^0.8.0 | Fee switch, UUPS | **Critical** | [S9](docs/contracts/session-09-v2-whitelist-switchable.md) |
| 10 | "Normal" Meme Token | ^0.8.0 | OZ ERC-20 + hidden control plane | **Critical** | [S10](docs/contracts/session-10-normal-meme-token.md) |
| 11 | Ownership-Renounce Token | 0.5.16 | Plain BEP-20 | Clean | [S11](docs/contracts/session-11-ownership-renounce-meme-token.md) |
| 12 | Auto-Renounce Token | ^0.8.0 | Minimal ERC-20 | Clean | [S12](docs/contracts/session-12-auto-ownership-renounce-meme-token.md) |
| 13 | Unlimited Supply Token | ^0.8.0 | S10 + `print` | **Critical** | [S13](docs/contracts/session-13-unlimited-supply-meme-token.md) |
| 14 | V2 Unlimited Supply | ^0.8.0 | S13, UUPS | **Critical** | [S14](docs/contracts/session-14-v2-unlimited-supply-meme-token.md) |
| 15 | V2 Auto-Renounce Token | ^0.8.0 | Minimal ERC-20 (constants) | Clean | [S15](docs/contracts/session-15-v2-auto-ownership-renounce-meme-token.md) |

"Verdict" refers to the source in this repository only. "Clean" means no indicator from the scanner and no privileged path found by manual reading; it is not an audit.

## Repository layout

```text
.
├── README.md
├── contracts/
│   ├── honeypot/    # Sessions 1–9
│   └── token/       # Sessions 10–15
├── docs/
│   ├── overview.md  SECURITY.md
│   ├── analysis/    # control-plane.md, errata.md
│   ├── reference/   # math.md, taxonomy.md, classic-honeypots.md, glossary.md
│   ├── guides/      # detection-playbook.md, getting-started.md, liquidity-lifecycle.md, risk-indicators.md
│   └── contracts/   # session-01 … session-15
└── tools/
    ├── scan_indicators.py       # static indicator scanner
    └── gen_session_pages.py     # regenerates docs/contracts/* from verified facts
```

The 14 classic bait contracts live in the separate `Honeypots-on-Blockchain` repository; its README should link here (a ready-made replacement README is provided as `HONEYPOTS-ON-BLOCKCHAIN-README.md`).

## Reproducing the findings

```bash
python3 -I tools/scan_indicators.py contracts/          # indicators per file
python3 -I tools/scan_indicators.py contracts/ --json   # machine-readable
```

Numeric examples in the math reference were reproduced with exact integer arithmetic; the wrap-around results for contracts `07` and `07a` were obtained by simulating `uint8` arithmetic.

## Limitations

* Static reading and regex scanning only; **no contract was compiled, deployed or executed** for this handbook (the sandbox had no compiler or network access). Behavioural statements about `uint8` wrap-around and compiler quirks follow Solidity 0.4 semantics as documented, and the on-chain outcomes cited by the original repository were not re-verified.
* The purpose of address **C** (the `exchange()` exclusion) cannot be determined from source.
* Contract sizes and line counts include comments and blank lines.

## Contact

For auditing and financial security, you can get in touch at [HackSprint](https://hacksprint.net/?v=5eb6b3df0442).
