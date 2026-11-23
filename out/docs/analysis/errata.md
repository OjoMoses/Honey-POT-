# Errata and Corrections to Earlier Documentation

The earlier documentation in this repository was written without reading each contract in full. This page lists what was wrong or misleading and where the corrected statement now lives. Contract facts were re-derived from source and the [indicator scanner](../guides/detection-playbook.md#2-static-triage-scanner).

## Substantive corrections

| # | Earlier statement | Correction | See |
|---|---|---|---|
| E1 | Sessions 10, 13, 14 described as "non-honeypot" / "normal" token examples | All three contain the hidden control plane: a hard-coded address accepted by `onlyOwner`, a role chain, several uncapped mint paths and double-credit helpers. Session 13 adds a public-looking `print` mint. They are **not** safe examples. | [S10](../contracts/session-10-normal-meme-token.md), [S13](../contracts/session-13-unlimited-supply-meme-token.md), [S14](../contracts/session-14-v2-unlimited-supply-meme-token.md) |
| E2 | Session 11 "Ownership-Renounce" grouped with the others | Session 11 is a standard BEP-20 with no indicators. Its renounce is real. | [S11](../contracts/session-11-ownership-renounce-meme-token.md) |
| E3 | "Ownership renounce" implied that privileges end | In Sessions 5–10, 13, 14 `renounceOwnership()` sets only the stored owner to zero; `onlyOwner` also accepts a hard-coded address, so privileges survive. Only Sessions 12 and 15 renounce inside the constructor with no other privileged path. | [Control plane §2](control-plane.md#2-the-latent-role-chain) |
| E4 | Session 1: "Owner-privileged transfer logic" | In Session 1 `onlyOwner` compares against a hard-coded address, **not** the stored `owner`; the deployer is allow-listed for selling but holds no owner power through that modifier. The sell restriction is on `transferFrom` only. | [S1](../contracts/session-01-honeypot-v1.md) |
| E5 | Solidity listed as "legacy" or "^0.8.x/legacy style" | Actual pragmas: S1–S2 `^0.4.26`; S3 `^0.8.19`; S4 none; S5, S11 `0.5.16`; S8 `^0.8.24`; S6, S7, S9, S10, S12–S15 `^0.8.0`. | Each session page |
| E6 | Session 9 "Selective exit control" | More precisely: owner-settable sell tax up to 100 % with a fee-exempt list for privileged addresses, on an upgradeable base with an unprotected initializer. | [S9](../contracts/session-09-v2-whitelist-switchable.md) |
| E7 | Session 4 described only as "whitelist + anti-bot" | The sell-limit variables in `condition()` are never assigned, so for non-exempt senders the check always fails. | [S4](../contracts/session-04-whitelist-antibot-honeypot.md) |
| E8 | "V2" implied an upgrade over the original | S8, S9, S14 are UUPS ports; S15 is **not** upgradeable (it only marks values `constant`). | Session pages |

## Naming collisions

The root-level files named `Session 1…4 - Upgraded V2 …` use a **different numbering** from `docs/contracts/session-NN-*`. Mapping (verified byte-identical with `cmp`):

| Root file | Organised copy |
|---|---|
| `Session 1 - Upgraded V2 Blacklist Honeypot Detector Proof.sol` | `contracts/honeypot/session-08-…` |
| `Session 2 - Upgraded V2 Whitelist Switch On-Off Honeypot Mode.sol` | `contracts/honeypot/session-09-…` |
| `Session 3 - Upgraded V2 Automatic Ownership Renounce Meme Token.sol` | `contracts/token/session-15-…` |
| `Session 4 - Upgraded V2 Unlimited Supply Printing Meme Token.sol` | `contracts/token/session-14-…` |

All 15 organised files are byte-identical to the corresponding root artifact files; the organised copies are canonical.

## Structural fixes

* Per-contract pages now follow one template: identification, mechanism, predicate, equations, detection signals, hard-coded addresses.
* Pages cross-reference the shared [taxonomy](../reference/taxonomy.md) and [math](../reference/math.md) instead of repeating generic text.
* The `Contact` footer, previously repeated on every page, appears once in the top-level README.
