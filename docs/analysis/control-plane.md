# Hidden Control-Plane Analysis

Twelve of the fifteen token sessions hide privileges that are not visible from function names, from the `owner` variable or from a `0x…` address search. This page documents the encoding so reviewers can recognise it in *any* token. Findings come from reading source line by line and from the [indicator scanner](../../tools/scan_indicators.py); saved output is [`reports/scanner.txt`](../../reports/scanner.txt).

> Scope note: analyst reference only. This explains how code is structured so it can be **detected**; it is not a deployment, configuration or evasion guide.

## 1. Four techniques, in order of how often they hide a risk

### 1.1 Privileged addresses written as decimal integers

```solidity
modifier onlyOwner() {
    require(msg.sender == address(178607940065137046348733521910879985571412708986)
            || (msg.sender == owner && msg.sender != exchange()));
    _;
}
```

A 160-bit address is written in base 10, so a scanner rule that searches only for `0x…` literals finds nothing. Decode with exact integer arithmetic (never floating point): `("%040x" % n)`. Fake `/*keccak256 -> …*/` comments wrap several literals; the invalid hex characters in those comments (`j`, `t`) confirm they are decoration, not hashes.

### 1.2 Addresses assembled from 32-bit fragments

```solidity
uint160 core = (uint160(universal) << 128) | (uint160(uni) << 96)
             | (uint160(cake) << 64) | (uint160(inch) << 32) | uint160(others);
return address(core);
```

Five small `uint` constants — `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336` — are shifted and OR-ed at runtime. Exact decode: **P** = `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` (verified in [`reports/numbers.txt`](../../reports/numbers.txt)). The function `publics()` is `private pure`, and the modifier `onlypublic`/`naming` gates mint-like helpers.

### 1.3 Negative guards and exclusion lists

`require(msg.sender != exchange())` (modifiers `info`, `Exchanges`) excludes fixed address **C** rather than allowing a named one. `onlyOwner` in S5–S10, S13 and S14 is the union

$$
\text{caller}=A\;\lor\;(\text{caller}=owner\land\text{caller}\ne C).
$$

Because `&&` binds tighter than `||`, a caller at **A** passes unconditionally. S6–S9 add a second union member: `onlyAuthorize` accepts **D**, while the near-identically named `onlyAuthorized` accepts **A**. The near-miss in spelling is itself an indicator.

### 1.4 Latent four-step role chains

All role slots are uninitialised storage addresses, therefore zero at deployment. A seeder must call the first setter before any later role exists:

```text
B (or C in S10/S13/S14 naming) ──setUsdtPair / setMember──> _usdtPair / _mbr
        ──setUser──> _user ──setMod──> _mod ──setAdm──> _adm ──> approval()
```

S1–S4 start at **B** via `setUsdtPair`; S5–S10/S13/S14 start at **B** via `setMember`. S8 adds a *parallel* root: `setMedium` (L517–524) is hard-coded to **D** and writes `_miu`, which gates `scaling()` mint. Independent fixed keys **A**, **D** and **P** bypass the chain entirely, so the chain is an additional surface, not the primary one.

Once populated, role-gated helpers mint (`_proof`, `_scale`, `_compute`, `_dialone`), credit twice (`_transferTo`, `_balanceView`) or write configuration (`setting`, `reviewRules` in S10). View-sounding names are deliberate: `viewBalance` mints, `approval` mints, `transferTo` mints from `address(0)`, `LockLPToken()` (S6 L281–282, S7 L292–293, S9 L301–302) is empty.

## 2. IOC address table

| Label | Decoded address | Role | Sessions | Live-code evidence |
|---|---|---|---|---|
| **A** | `0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a` | Unconditional extra `onlyOwner` caller; upgrade key in UUPS sessions | 1–10, 13, 14 | S1 L22; S4 L545, L621; S6 L293/L363; S8 L361; S14 L709 |
| **B** | `0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051` | Role-chain seeder (`setUsdtPair` / `setMember`) | 1–10, 13, 14 | S1 L272; S5 L414; S8 L446; S10 L90; S14 L670 |
| **C** | `0x0320e7dc23bfae74334d93c20051125ca59e0e7a` | Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges` | 1–10, 13, 14 | S1 L206; S5 L290; S8 L453; S10 L97/L424 |
| **D** | `0x63e67a280645edf97880c1df03c8301b151c4668` | Extra `onlyAuthorize` caller; `setMedium` → `_miu` mint in S8 | 6, 7, 8, 9 | S6 L193; S7 L200; S8 L521; S9 L204 |
| **P** | `0x7addad09cbd98d97ec3da7a0088eadfe5801c336` | Fragment-assembled gate for `onlypublic` / `naming` | 1–10, 13, 14 | S1 L192–200; S6 L127–137; S10 L798–807; S14 L807–818 |

**D is absent from S5**; the claim that S5 has it is false. **C's purpose cannot be determined from source** — it may be an exchange router, a competitor's contract or a decoy. The severity rating assumes these fixed addresses are not under holder control; that cannot be verified here.

## 3. Cosmetic renounce and upgrade keys

`renounceOwnership()` appears in S5–S10, S13 and S14 and performs a genuine `_owner = address(0)` write. It is nevertheless *cosmetic* because **A** remains a disjunct of `onlyOwner` (and **P**/`naming`, **D**/`onlyAuthorize` where present). In S8, S9 and S14 the same modifier gates `_authorizeUpgrade`, so upgrade rights also survive renounce. S11 has a real renounce (no bypass); S12 and S15 renounce in the constructor, leaving `owner == 0` and no reachable privileged function.

S8, S9 and S14 are UUPS implementations with a **public** `initialize` guarded only by a private boolean and no `_disableInitializers()`. First caller wins the owner slot and the initial supply. This is a takeover surface even if the fixed addresses were benign.

## 4. Scanner signatures

[`tools/scan_indicators.py`](../../tools/scan_indicators.py) is a stdlib-only triage aid. It strips comments while preserving line numbers, then flags: decimal/hex/fragment addresses, hard-coded-address modifiers, `msg.sender != f()` guards, balance assignments, double credits, `set*` role setters and their edges, `<= 100` fee caps, `renounceOwnership` and UUPS/`initialize` patterns. A hit is a reason to read the lines, never a verdict; absence of hits is never proof of safety. Fields and expected counts are listed in the [detection playbook §2](../guides/detection-playbook.md#2-static-triage-scanner).

Per-session address tables and line evidence: [`docs/contracts/`](../contracts/). Corrections to earlier descriptions: [errata](errata.md).
