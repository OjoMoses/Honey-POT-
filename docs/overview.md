# Documentation Overview

Each question has one home. Pages are generated from the fact table in `tools/gen_handbook.py` where noted.

```text
README.md                    findings, verified index, layout
docs/
├── SECURITY.md              responsible use
├── overview.md              this page
├── analysis/
│   ├── control-plane.md     privilege encoding and IOC table
│   └── errata.md            corrections; duplicate-file mapping
├── reference/
│   ├── math.md              equations + worked examples
│   ├── taxonomy.md          T1–T9, B1–B4; severity model
│   ├── classic-honeypots.md catalog (sources not attached)
│   └── glossary.md          terms and references
├── guides/
│   ├── detection-playbook.md procedure, scanner, fork test, reporting
│   ├── getting-started.md   orientation
│   ├── liquidity-lifecycle.md pool concepts
│   └── risk-indicators.md   red-flag checklist
└── contracts/               one generated page per session (1–15)
```

## Reading paths

* **New to honeypots:** [getting-started](guides/getting-started.md) → [taxonomy](reference/taxonomy.md) → [detection playbook](guides/detection-playbook.md) → [control plane](analysis/control-plane.md).
* **Quantitative:** [math](reference/math.md) → any [session page](contracts/) → [liquidity lifecycle](guides/liquidity-lifecycle.md).
* **Teaching the classics:** [classic honeypots](reference/classic-honeypots.md) → [math §6](reference/math.md#6-classic-honeypot-arithmetic) (sources not attached).

## Conventions

* Sessions are numbered 1–15 as in `contracts/`. The root-level `Session 1…4 - Upgraded V2 …` files use a different numbering; see the [errata mapping](analysis/errata.md#naming-collisions).
* Labels **A, B, C, D, P** denote the recurring fixed or assembled addresses in the [control-plane table](analysis/control-plane.md#11-privileged-addresses-written-as-decimal-integers).
* Threat IDs are defined in the [taxonomy](reference/taxonomy.md). Equations use GitHub-flavoured `$…$` / `$$…$$`.
* Every contract claim is tied to a source line or scanner output; unresolvable questions are stated as limitations.

## Maintenance

Edit `tools/gen_handbook.py` (the single fact table), rerun it, then rerun the scanner, number verification and link checker. Do not hand-edit generated session pages or the README index.
