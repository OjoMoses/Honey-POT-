# Getting Started

A one-page orientation for someone about to review these contracts.

## What you need

| Item | Why |
|---|---|
| Python 3.8+ | Run `tools/scan_indicators.py` (no third-party packages) |
| Foundry (`forge`, `anvil`, `cast`) or Hardhat | Local fork, impersonation, address/hex conversion (`cast to-hex`) |
| Solidity compilers 0.4.26, 0.5.16, 0.8.x (e.g. via `svm`/`solc-select`) | Match each file's pragma; the classic baits need the exact historical version |
| An archive-node RPC (optional) | Fork a real chain to test a deployed token |

## First hour

1. Read the [README findings](../../README.md#key-findings) and the [taxonomy](../reference/taxonomy.md).
2. Run the scanner on `contracts/` and compare with the [expected results](detection-playbook.md#2-static-triage-scanner).
3. Open [Session 1](../contracts/session-01-honeypot-v1.md) and [Session 12](../contracts/session-12-auto-ownership-renounce-meme-token.md) side by side — the most hostile and the cleanest — and note every difference in the privileged surface.
4. Read [control-plane](../analysis/control-plane.md) §1–2 and decode one decimal literal yourself (`python3 -c "print(hex(178607940065137046348733521910879985571412708986))"`).
5. Work through [math](../reference/math.md) §3–5 using a pool of your own numbers.

## Ground rules

* Source labels, file names and comments are claims, not evidence.
* Prefer the dynamic test over reading when the two disagree, and re-run it after privileged transactions.
* A "no findings" result applies to a block number, not to the contract forever.

## Review checklist (short form)

- [ ] Compiler/bytecode match the explorer
- [ ] Every privileged modifier read in full, including literals and negative guards
- [ ] All mint, burn, overwrite and fee paths enumerated; who can reach each?
- [ ] Role chains traced to an externally-owned account
- [ ] Sell simulated through the router from two fresh addresses, before and after privileged calls
- [ ] $\sum$ balances vs `totalSupply` compared
- [ ] Proxy/upgrade authority identified
- [ ] Findings recorded with file/line, capability, reproduction

Long form: [Detection playbook](detection-playbook.md).
