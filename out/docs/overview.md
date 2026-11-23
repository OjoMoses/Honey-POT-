# Documentation Overview

This handbook is organised so each question has one home.

```text
README.md                   findings, index, layout
docs/
├── SECURITY.md             responsible use, safe handling
├── overview.md             this page
├── analysis/
│   ├── control-plane.md    how hidden privileges are encoded; IOC table
│   └── errata.md           corrections to earlier docs; file-name mapping
├── reference/
│   ├── math.md             equations + worked examples
│   ├── taxonomy.md         threat classes T1–T9, B1–B4; severity model
│   ├── classic-honeypots.md  the 14 classic bait contracts
│   └── glossary.md         terms and references
├── guides/
│   ├── getting-started.md  orientation and ground rules
│   ├── detection-playbook.md  procedure, scanner, fork test, reporting
│   ├── liquidity-lifecycle.md pool concepts and review points
│   └── risk-indicators.md  red-flag checklist
└── contracts/              one page per token session (1–15)
```

## Reading paths

* **Auditor new to honeypots:** getting-started → taxonomy → detection-playbook → control-plane → any two session pages.
* **Quantitative reader:** math → session pages (each links its equations) → liquidity-lifecycle.
* **Teaching the classics:** classic-honeypots → math §6 → taxonomy B-classes.

## Conventions

* **Sessions** are numbered 1–15 as in `contracts/`. The four root files named `Session 1…4 - Upgraded V2…` use a different numbering; see the [mapping](analysis/errata.md#naming-collisions).
* **Labels A, B, C, D, P** denote the recurring hard-coded or assembled addresses ([table](analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers)).
* **Threat IDs** T1–T9 (tokens) and B1–B4 (bait contracts) are defined in the [taxonomy](reference/taxonomy.md).
* Equations use GitHub-flavoured `$…$` / `$$…$$` LaTeX.
* Every statement about a contract was derived from its source; where something could not be determined, the page says so.

## Maintenance

`tools/gen_session_pages.py` regenerates the 15 session pages from a single verified fact table; edit the table, not the generated Markdown. After any change to a contract, rerun the scanner and compare with the [scanner results](guides/detection-playbook.md#2-static-triage-scanner).
