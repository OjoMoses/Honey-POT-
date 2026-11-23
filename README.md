# Smart-Contract Honeypot Research Handbook

Defensive documentation for the 15 token contracts in [`contracts/`](contracts/), extracted from the attached `out/` archive. The purpose is to help analysts **recognise and detect** hidden privilege and honeypot behaviour from source and from a local fork.

> **Responsible use.** Scope is analysis and detection only. Do not deploy, adapt, configure or market any contract here as safe, and do not use these findings to evade scanners. Work on a local fork with throw-away keys. See [SECURITY](docs/SECURITY.md).

## Key findings

1. **12 of 15 sessions carry a hidden control plane** (S1–S10, S13, S14): decimal or fragment-assembled privileged addresses, a four-step dormant role chain, uncapped mint or balance-assign paths and double-credit helpers. S11, S12 and S15 show no such indicator in source or scanner output.
2. **File names and labels are unreliable.** `normal-meme-pepe-token-non honeypot-code` (S10) and the `unlimited supply printing … non honeypot-code` artifact (S13) are backdoored. `renounceOwnership()` in S5–S10, S13 and S14 is cosmetic: `onlyOwner` also accepts address **A**.
3. **Any reachable uncapped mint approximates a pool drain.** Selling $m$ new tokens removes the fraction $\frac{\gamma m}{x+\gamma m}$ of the quote reserve, which tends to 1 as $m$ grows ([Math §5](docs/reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)).
4. **Sell tests must be path- and state-aware.** Fees are charged in `transferFrom` but not `transfer` (S6–S9); the blacklist (S5, S8, S10, S13, S14) and fee-exempt list (S7, S9) are writable after deployment. A single fresh-address test proves little ([Playbook §4](docs/guides/detection-playbook.md#4-dynamic-test-on-a-fork)).
5. **Compiler version is not a safety signal.** S3 is a `^0.8.19` port of the S1/S2 gate; S8, S9 and S14 are UUPS implementations with a public first-caller-wins `initialize`.
6. **S14 has a second supply-reporting defect:** public `totalSupply` is a separate variable from the ERC-20 private `_totalSupply`, so later mint helpers do not change the reported value ([S14](docs/contracts/session-14-v2-unlimited-supply-meme-token.md)).

## Verified session index

<!-- INDEX:START -->
| Session | Solidity | Family | Verdict | Page |
|---|---|---|---|---|
| 1 | `^0.4.26` | 1 — allow-list sell gate | **Critical** — Honeypot / backdoored | [S1](docs/contracts/session-01-honeypot-v1.md) |
| 2 | `^0.4.26` | 1 — allow-list sell gate | **Critical** — Honeypot / backdoored | [S2](docs/contracts/session-02-honeypot-v1-2.md) |
| 3 | `^0.8.19` | 1 — allow-list sell gate | **Critical** — Honeypot / backdoored | [S3](docs/contracts/session-03-honeypot-v1-solidity-0.8.19.md) |
| 4 | `^0.5.17` | 2 — anti-bot condition | **Critical** — Honeypot / permanently locked | [S4](docs/contracts/session-04-whitelist-antibot-honeypot.md) |
| 5 | `0.5.16` | 3 — blacklist, BEP-20 | **Critical** — Honeypot / selective freeze | [S5](docs/contracts/session-05-blacklist-detector-proof-honeypot.md) |
| 6 | `^0.8.0` | 4 — fee switch | **Critical** — Honeypot / 100% fee | [S6](docs/contracts/session-06-switchable-honeypot-mode.md) |
| 7 | `^0.8.0` | 4 — fee switch + exemption | **Critical** — Honeypot / 100% fee, exempt insiders | [S7](docs/contracts/session-07-whitelist-switchable-honeypot.md) |
| 8 | `^0.8.24` | 3 — blacklist, UUPS | **Critical** — Honeypot / UUPS + blacklist | [S8](docs/contracts/session-08-v2-blacklist-detector-proof.md) |
| 9 | `^0.8.0` | 4 — fee switch, UUPS | **Critical** — Honeypot / UUPS + 100% fee | [S9](docs/contracts/session-09-v2-whitelist-switchable.md) |
| 10 | `^0.8.0` | 5 — OZ ERC-20 + trade limits | **Critical** — Backdoored / label false | [S10](docs/contracts/session-10-normal-meme-token.md) |
| 11 | `0.5.16` | Clean — plain BEP-20 | **Informational** — No hidden privilege found | [S11](docs/contracts/session-11-ownership-renounce-meme-token.md) |
| 12 | `^0.8.0` | Clean — minimal ERC-20 | **Informational** — No hidden privilege found | [S12](docs/contracts/session-12-auto-ownership-renounce-meme-token.md) |
| 13 | `^0.8.0` | 5 — OZ ERC-20 + `print` | **Critical** — Backdoored / uncapped mint | [S13](docs/contracts/session-13-unlimited-supply-meme-token.md) |
| 14 | `^0.8.0` | 5 — UUPS + `print` | **Critical** — Backdoored / UUPS + uncapped mint | [S14](docs/contracts/session-14-v2-unlimited-supply-meme-token.md) |
| 15 | `^0.8.0` | Clean — minimal ERC-20 (constants) | **Informational** — No hidden privilege found | [S15](docs/contracts/session-15-v2-auto-ownership-renounce-meme-token.md) |
<!-- INDEX:END -->

"Verdict" applies to the source in this repository only. "Clean" means no indicator from the scanner and no privileged path found by manual reading — it is not an audit of any deployed contract.

## Documentation map

| Need | Go to |
|---|---|
| Orientation and conventions | [Overview](docs/overview.md) |
| Equations with checked examples | [Math reference](docs/reference/math.md) |
| Threat classes and severity | [Taxonomy](docs/reference/taxonomy.md) |
| Encoded privileges and IOC addresses | [Control plane](docs/analysis/control-plane.md) |
| Corrections to the earlier docs | [Errata](docs/analysis/errata.md) |
| Classic bait contracts (sources not attached) | [Classic honeypots](docs/reference/classic-honeypots.md) |
| Review procedure, scanner, fork test, report template | [Detection playbook](docs/guides/detection-playbook.md) |
| One page per session | [`docs/contracts/`](docs/contracts/) |
| Terms and references | [Glossary](docs/reference/glossary.md) |

## Repository layout

```text
.
├── README.md, HONEYPOTS-ON-BLOCKCHAIN-README.md
├── contracts/
│   ├── honeypot/   # sessions 01–09
│   └── token/      # sessions 10–15
├── docs/
│   ├── SECURITY.md, overview.md
│   ├── analysis/   # control-plane.md, errata.md
│   ├── reference/  # math.md, taxonomy.md, classic-honeypots.md, glossary.md
│   ├── guides/     # detection-playbook.md + orientation guides
│   └── contracts/  # 15 generated session pages
├── tools/
│   ├── scan_indicators.py    # static IOC scanner (stdlib only)
│   ├── verify_numbers.py     # exact-integer verification of every figure
│   ├── gen_handbook.py       # fact table -> session pages and indexes
│   ├── inventory.py          # file inventory and duplicate comparison
│   └── check_links.py        # Markdown link/anchor checker
└── reports/
    ├── scanner.txt, scanner.json
    ├── numbers.txt, inventory.txt, duplicates.txt, links.txt
```

## Reproducing the findings

```bash
python3 -I tools/scan_indicators.py contracts/ --out reports/scanner.txt
python3 -I tools/scan_indicators.py contracts/ --json --out reports/scanner.json
python3 -I tools/verify_numbers.py --out reports/numbers.txt
python3 -I tools/gen_handbook.py .
python3 -I tools/inventory.py <rootA> <rootB> --inv reports/inventory.txt --dup reports/duplicates.txt
python3 -I tools/check_links.py . --out reports/links.txt
```

## Limitations

* Static source reading and regex scanning only: **no contract was compiled, deployed or executed** here. Behavioural claims are derived from source and exact arithmetic; see the [playbook](docs/guides/detection-playbook.md) for the fork test that would confirm them dynamically.
* The 14 classic bait contracts described in the [catalog](docs/reference/classic-honeypots.md) are **not present in the attached archive**. Those entries document pre-existing claims and cannot be re-verified against source.
* The purpose of address **C** (the negative `exchange()` guard) cannot be determined from source. Reported severity assumes the fixed addresses are not under holder control.
* Line counts include comments and blank lines. The archive copies are LF-normalised; copies elsewhere in the source repository are CRLF but code-identical ([errata](docs/analysis/errata.md#duplicate-copies-and-line-endings)).
