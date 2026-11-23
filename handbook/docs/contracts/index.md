# Contract reference index

[Handbook home](../../README.md) · [Detection playbook](../guides/detection-playbook.md) · [Taxonomy](../reference/taxonomy.md)

This index and every page under `docs/contracts/` are generated from `tools/contract_facts.py` by `tools/gen_session_pages.py`.

- `malicious`: **8**
- `broken`: **4**
- `clean` (source scope): **3**

The `broken` label is not a safety endorsement. It means dangerous hidden-control patterns are present and the code also contains an internal defect that changes the intended path (for example, a `buy()` that never pays ETH or an initializer that double-counts supply).

| Session | Short title | Pragma | Classification | Verdict |
|---|---|---|---|---|
| [01](session-01-honeypot-v1.md) | Honeypot V1 — hard-coded owner, overwrite mint, double-credit | `^0.4.26` | Malicious hidden control | `malicious` |
| [02](session-02-honeypot-v1-2.md) | Honeypot V1.2 — same control plane with a cleaner constructor | `^0.4.26` | Malicious hidden control | `malicious` |
| [03](session-03-honeypot-v1-solidity-0.8.19.md) | Honeypot V1 for Solidity 0.8.19 — compiled-era syntax, same trap | `^0.8.19` | Malicious hidden control | `malicious` |
| [04](session-04-whitelist-antibot-honeypot.md) | Whitelist anti-bot honeypot — exit only for `canSale` addresses | `^0.5.17` | Malicious hidden control (whitelist trap) | `malicious` |
| [05](session-05-blacklist-detector-proof-honeypot.md) | Blacklist + detector-proof honeypot — hard-coded owner and mint paths | `0.5.16` | Malicious hidden control | `malicious` |
| [06](session-06-switchable-honeypot-mode.md) | Switchable mode — token-side fees, ETH sink, and hidden minters | `^0.8.0` | Malicious hidden control and broken fee accounting | `broken` |
| [07](session-07-whitelist-switchable-honeypot.md) | Whitelist-switchable honeypot — fee exemptions, not an exit whitelist | `^0.8.0` | Malicious hidden control and broken fee accounting | `broken` |
| [08](session-08-v2-blacklist-detector-proof.md) | V2 blacklist honeypot — UUPS proxy, public initialize, D-gated mint | `^0.8.24` | Malicious hidden control (upgradeable) | `malicious` |
| [09](session-09-v2-whitelist-switchable.md) | V2 whitelist-switchable — UUPS fee token with hidden minters | `^0.8.0` | Malicious hidden control (upgradeable) | `broken` |
| [10](session-10-normal-meme-token.md) | “Normal” meme token — full hidden control plane under an OZ-looking shell | `^0.8.0` | Malicious hidden control (mislabeled as normal) | `malicious` |
| [11](session-11-ownership-renounce-meme-token.md) | Ownership-renounce meme token — conventional fixed-supply BEP-20 | `0.5.16` | No hidden control found (clean in scope) | `clean` |
| [12](session-12-auto-ownership-renounce-meme-token.md) | Auto-renounce meme token — fixed supply, owner revoked in constructor | `^0.8.0` | No hidden control found (clean in scope) | `clean` |
| [13](session-13-unlimited-supply-meme-token.md) | Unlimited-supply meme token — Session 10 plus owner `print` mint | `^0.8.0` | Malicious hidden control | `malicious` |
| [14](session-14-v2-unlimited-supply-meme-token.md) | V2 unlimited-supply meme token — UUPS, public initialize, double supply | `^0.8.0` | Malicious hidden control (upgradeable, defective initialization) | `broken` |
| [15](session-15-v2-auto-ownership-renounce-meme-token.md) | V2 auto-renounce meme token — constants, fixed supply, no proxy | `^0.8.0` | No hidden control found (clean in scope) | `clean` |

## Reading order for a defender

1. Read [taxonomy](../reference/taxonomy.md) to separate bait, exit gates, and accounting bugs.
2. Read [control-plane](../analysis/control-plane.md) for the A/B/C/D/P address map and role chains.
3. Read the session pages for the contracts in scope.
4. Use the [detection playbook](../guides/detection-playbook.md) and the scanner output in [`reports/scan.txt`](../../reports/scan.txt).
5. Read [errata](../analysis/errata.md) before trusting the older `docs/` tree or the `out/` directory.

## Scope boundary

No Solidity compiler was available. Pages describe source semantics and static indicators; they do not certify bytecode, proxy storage, or live liquidity. No deployment, transaction, mempool, or fork execution was performed.
