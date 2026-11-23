#!/usr/bin/env python3
"""Single source of truth for session facts; generates contract pages + indexes.

Standard library only. Edit FACTS, then run:
    python3 tools/gen_handbook.py <repository-root>

Generated: docs/contracts/session-*.md, the README index block, and docs/overview.md.
"""
from __future__ import annotations

import pathlib
import sys

A = "0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a"
B = "0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051"
C = "0x0320e7dc23bfae74334d93c20051125ca59e0e7a"
D = "0x63e67a280645edf97880c1df03c8301b151c4668"
P = "0x7addad09cbd98d97ec3da7a0088eadfe5801c336"

ADDR_DEC = {
    "A": "178607940065137046348733521910879985571412708986",
    "B": "686197854011229533619447624007587113080310915153",
    "C": "17860794006513704634733521910879985571412708986",
    "D": "570329899025738970963394674811034510039273195112",
}
ADDR_HEX = {"A": A, "B": B, "C": C, "D": D, "P": P}
ADDR_ROLE = {
    "A": "Unconditional extra caller in `onlyOwner`, `onlyAuthorized` (S1–10, 13, 14)",
    "B": "Seeder: only caller of `setUsdtPair`/`setMember`; starts the role chain",
    "C": "Returned by `exchange()`/`contracts()`/`exchanger()`; excluded by `info`/`Exchanges`",
    "D": "Extra caller in `onlyAuthorize` (S6–S9) and `setMedium` (S8)",
    "P": "Assembled at runtime by `publics()`; gates `onlypublic`/`naming`",
}
ADDR_EVIDENCE = {
    "A": "S1 L22; S2 L107; S3 L165; S4 L545,621; S5 L317; S6 L293,363; S7 L304,387; S8 L361; S9 L313,395; S10 L122; S13 L122; S14 L709",
    "B": "S1 L272; S2 L258; S3 L398; S4 L376; S5 L414; S6 L97; S7 L100; S8 L446; S9 L110; S10 L90; S13 L90; S14 L670",
    "C": "S1 L206; S2 L197; S3 L302; S4 L511; S5 L290; S6 L150; S7 L154; S8 L453; S9 L163; S10 L97,424; S13 L97,424; S14 L308,684",
    "D": "S6 L193; S7 L200; S8 L521; S9 L204",
    "P": "S1 L192–200; S2 L183–191; S3 L280–294; S4 L585–599; S5 L425–436; S6 L127–137; S7 L130–140; S8 L381–392; S9 L139–150; S10 L798–807; S13 L797–806; S14 L807–818",
}

MATH = "../reference/math.md"
PLAIN = "$P \\equiv \\text{true}$ (subject only to balance and zero-address checks); no fee, list or privileged gate."


def F(n, slug, title, cat, sub, root, pragma, lines, family, tags, sev, verdict,
      summary, mech, pred, eq, detect, addresses, evidence):
    return dict(n=n, slug=slug, title=title, cat=cat, sub=sub, root=root,
                pragma=pragma, lines=lines, family=family, tags=tags, sev=sev,
                verdict=verdict, summary=summary, mech=mech, pred=pred, eq=eq,
                detect=detect, addresses=addresses, evidence=evidence)


FACTS = [
    F(1, "honeypot-v1", "Honeypot Token V1", "honeypot", "honeypot", "honeypot-smart-contract",
      "^0.4.26", 284, "1 — allow-list sell gate", "T1 T4 T5 T6 T9", "Critical", "Honeypot / backdoored",
      "`transfer` moves tokens freely, but router sells use `transferFrom`, which additionally requires `allow[_from] == true`. Only the deployer is allow-listed at construction (L97); every ordinary holder's router sale reverts.",
      [
        "`onlyOwner` (L17–24) requires `msg.sender == A` and never reads the stored `owner`; `owner` is decorative (L13, L29).",
        "`transfer` (L130–140) checks only zero-address and balance; `transferFrom` (L168–184) adds allowance and `allow[_from]` (L176).",
        "`mint` (L281–283, `onlyOwner`) calls `_mint`, which **assigns** `balances[miner] = _value` (L219). `approveAndCall` (L243–252, `_adm`) and `adjust` (L222–225, **P**) also assign balances (L249, L265).",
        "`_transferTo` (L101–108) and `_balanceView` (L117–124) each credit the target twice and emit two `Transfer(0, …)` events without raising `totalSupply`.",
        "Four-step dormant chain: B → `_usdtPair` (L268–274) → `_user` (L153–156) → `_mod` (L238–241) → `_adm` (L213–216). All role slots default to zero.",
        "Negative guards: `info` excludes C (L112–115); `contracts()` returns C (L203–207). `publics()` assembles P (L190–201).",
      ],
      "$P_{\\texttt{transfer}}(h,t,v)=[t\\ne 0]\\land[v\\le b(h)]$; $P_{\\texttt{transferFrom}}(h,t,v)=P_{\\texttt{transfer}}\\land[v\\le allowed[h][\\text{caller}]]\\land\\texttt{allow}[h]$.",
      f"[Math §3]({MATH}#3-sellability-predicate-and-honeypot-classification), [§4]({MATH}#4-supply-invariants-and-the-double-credit-defect), [§5]({MATH}#5-dilution-and-pool-drain-from-hidden-minting)",
      ["Fresh-address router sell reverts while a wallet-to-wallet `transfer` succeeds.",
       "Scanner: 3 unique decimal addresses (6 occurrences), fragment assembly, hard-coded address in `onlyOwner`, 2 double-credit helpers, 3 role edges.",
       "Two `Transfer(address(0),…)` events per helper call; sum of balances exceeds `totalSupply()`."],
      ["A", "B", "C", "P"],
      "L17–24, L101–124, L130–140, L153–156, L168–184, L190–207, L213–283"),

    F(2, "honeypot-v1-2", "Honeypot Token V1.2", "honeypot", "honeypot", "honeypot-contract-V1.2",
      "^0.4.26", 265, "1 — allow-list sell gate", "T1 T4 T5 T6 T9", "Critical", "Honeypot / backdoored",
      "Near-clone of Session 1: same sell gate, same address set, same role chain and double-credit helpers. Adds a pure `showuint160(address)` helper and routes `approveAndCall` through `_approvals`, which adds the `info` (≠ C) guard absent in Session 1.",
      [
        "`transfer` (L93–101) unrestricted; `transferFrom` (L163–174) requires `allow[_from]` (L167).",
        "`onlyOwner` accepts A (L103–110); `info` excludes C (L116–120); `onlypublic` accepts P (L143–147).",
        "`mint` (L262–264) → `_mint` assignment (L210); `approveAndCall` (L236–240, `_adm`) → `_approvals` assignment (L219) **with** `info`; `adjust` (L213–216) → `_dialone` (L251).",
        "`_transferTo` (L76–83) and `_balanceView` (L122–129) double-credit (L78/L81 and L124/L127).",
        "Chain B → `_usdtPair` (L254–260) → `_user` (L149–152) → `_mod` (L229–232) → `_adm` (L204–207). Role slots start zero.",
        "Pure `showuint160` (L72–74) is a conversion helper, not a safety feature.",
      ],
      "Same as Session 1; `P` for `transferFrom` additionally includes `allow[_from]`.",
      f"[Math §3]({MATH}#3-sellability-predicate-and-honeypot-classification), [§4]({MATH}#4-supply-invariants-and-the-double-credit-defect)",
      ["Diff against Session 1 shows only restructuring, `showuint160`, the extra `info` guard on `_approvals`, and an unused `sellOutNum`.",
       "Router sell from a fresh address reverts; direct `transfer` works."],
      ["A", "B", "C", "P"],
      "L72–74, L76–129, L93–120, L143–174, L204–264"),

    F(3, "honeypot-v1-solidity-0.8.19", "Honeypot Token V1 (Solidity 0.8.19)", "honeypot", "honeypot", "honeypot-smart-contract-0.8.19",
      "^0.8.19", 409, "1 — allow-list sell gate", "T1 T4 T5 T6 T9", "Critical", "Honeypot / backdoored",
      "Session 2 recompiled for `^0.8.19`. The privileged surface is unchanged; checked arithmetic now makes the two double-credit helpers revert on overflow instead of wrapping, and the four role setters return `true` instead of the default `false`.",
      [
        "Same `transfer` / `transferFrom` predicate as Sessions 1–2 (L142–158, L247–269).",
        "`onlyOwner` A (L160–168), `info` ≠ C (L176–182), `onlypublic` P (L217–223).",
        "Assignment-based mint/overwrite paths: `_mint` L323, `_approvals` L337, `approveAndCall` L366, `_dialone` L384.",
        "Double-credit helpers L120/L124 and L188/L192; in 0.8 these `+=` operations revert when the sum exceeds $2^{256}-1$.",
        "Chain B → `_usdtPair` (L394–402) → `_user` (L225–232) → `_mod` (L354–362) → `_adm` (L312–319).",
        "SafeMath is retained (assert-based) although 0.8 adds checked arithmetic; a modern compiler is not a safety signal.",
      ],
      "Identical to Sessions 1–2; the arithmetic-consequence difference is noted in the mechanism.",
      f"[Math §3]({MATH}#3-sellability-predicate-and-honeypot-classification), [§4]({MATH}#4-supply-invariants-and-the-double-credit-defect)",
      ["Scanner reports the same address family as S1–S2 under a modern pragma.",
       "Compare compiled behaviour of `viewBalance` against Session 2 on a fork: 0.8 checked arithmetic changes the overflow outcome."],
      ["A", "B", "C", "P"],
      "L117–196, L217–269, L278–325, L312–408"),

    F(4, "whitelist-antibot-honeypot", "Whitelist + Anti-Bot Honeypot", "honeypot", "honeypot", "whitelist-antibot-smart-contract",
      "^0.5.17", 693, "2 — anti-bot condition", "T1 T5 T6 T9", "Critical", "Honeypot / permanently locked",
      "A DevToken with a decoy OpenZeppelin stack. `ensure()` exempts the owner, `tradeAddress` and `canSale` holders; everyone else hits `condition()`, which returns `false` forever because `_saleNum`, `_minSale` and `_maxSale` are declared but never assigned (L608, L610, L612).",
      [
        "`transfer` (L357–361) delegates to `transferFrom(msg.sender,…)`, so it still hits `ensure` (L463).",
        "`ensure` (L405–419) exemptions: `from == owner`, `to == owner`, `from == tradeAddress`, `canSale[from]`; otherwise `require(condition(...))`.",
        "`condition` (L555–581) returns `false` at L557 when the three limit variables are zero; no setter writes them, so the branch is permanent.",
        "`_computing` (L363–369), `_approvals` (L382–388) and `_approvecall` (L490–496) assign `balanceOf[spender]` and set `canSale[spender] = true`.",
        "`_transferTo` (L390–401) double-credits (L394/L398) and emits two zero-address `Transfer` events.",
        "Chain B → `_usdtPair` (L371–380) → `_user` (L423–429) → `_mod` (L531–537) → `_adm` (L499–505); independent roots A (L545, L621), owner (L616, L631) and P (L351, L431, L482).",
        "`transferownership` (L631–639) does **not** change owner; it writes `tradeAddress` (L635). `transfer`, `transferFrom`, `approve` and the constructor are `payable`.",
      ],
      "For $v>0$ and $h\\notin\\mathcal{W}$: $P(h,t,v)=\\texttt{false}$ unconditionally, because $\\texttt{condition}\\equiv\\texttt{false}$. $\\mathcal{W}=\\{\\texttt{owner},\\texttt{tradeAddress}\\}\\cup\\{x:\\texttt{canSale}[x]\\}$.",
      f"[Math §3]({MATH}#3-sellability-predicate-and-honeypot-classification), [§4]({MATH}#4-supply-invariants-and-the-double-credit-defect)",
      ["Any non-exempt transfer reverts regardless of amount, block number or `allowance`.",
       "Search the whole file: `_saleNum`, `_minSale`, `_maxSale` have declarations but zero assignments.",
       "`payable` on ERC-20 entry points and an unused OpenZeppelin stack are review red flags."],
      ["A", "B", "C", "P"],
      "L343–349, L357–361, L371–505, L507–627, L631–693"),

    F(5, "blacklist-detector-proof-honeypot", "Blacklist + Detector-Proof Honeypot", "honeypot", "honeypot", "honeypot-scanner-detector-proof-token",
      "0.5.16", 741, "3 — blacklist, BEP-20", "T3 T4 T5 T6 T7 T9", "Critical", "Honeypot / selective freeze",
      "Standard-looking BEP-20 whose `_transfer` rejects a **blacklisted sender** (L637) with the misleading reason `\"Recipient is Gwei\"`. `zap`/`dezap` (L708–718) are `onlyOwner`, and `onlyOwner` also accepts A, so a fresh-address test passes until the holder is targeted.",
      [
        "`onlyOwner` (L314–322) accepts A or stored owner (unless it is C); `Exchanges` excludes C (L383–386); `onlypublic` accepts P (L394–397).",
        "`_transfer` (L636–644) checks `!isBlacklisted[sender]`, zero addresses and balance; 1:1 credit, no fee. `transfer` and `transferFrom` share this path.",
        "Uncapped mint: `_calculate` (L476–482) via `symbols` (L544–547, `onlypublic`); `_proof` (L655–661) via `approval` (L562–566, `_adm`) and `proof` (L682–685, `onlyOwner`).",
        "`_transferTo` (L438–445) and `_balanceView` (L462–469) double-credit. `_burn`/`_burnFrom` are internal-only.",
        "Chain B → `_mbr` (L410–416) → `_user` (L450–453) → `_mod` (L471–474) → `_adm` (L498–501), all zero at deployment; P is an independent role.",
        "`renounceOwnership` (L331–334) zeroes the stored owner but A still passes `onlyOwner`. Comment at L328–329 claims the opposite.",
      ],
      "$P(h)=[\\neg\\texttt{isBlacklisted}[h]]\\land[h\\ne 0]\\land[t\\ne 0]\\land[v\\le b(h)]$; `isBlacklisted` is writable by A or the stored owner at any time.",
      f"[Math §3]({MATH}#3-sellability-predicate-and-honeypot-classification), [§5]({MATH}#5-dilution-and-pool-drain-from-hidden-minting)",
      ["A fresh address sells successfully; the same address fails after a privileged `zap` transaction.",
       "Error string says `Recipient` while the require checks `sender`.",
       "No D in this file: D appears from Session 6 onward."],
      ["A", "B", "C", "P"],
      "L288–322, L331–397, L410–501, L511–661, L674–729"),

    F(6, "switchable-honeypot-mode", "Switchable Honeypot Mode", "honeypot", "honeypot", "switch on&off honeypot mode-honeypot-scanner-detector-proof-token",
      "^0.8.0", 369, "4 — fee switch", "T2 T4 T5 T6 T7 T9", "Critical", "Honeypot / 100% fee",
      "`transfer` is fee-free; `transferFrom` charges `fee = amount * sellFee / 100` to `address(this)`. Five setters allow `sellFee = 100`, at which point the router seller receives nothing. No fee-exempt list exists in this session.",
      [
        "`transfer` (L73–82) moves the full amount; `transferFrom` (L200–224) debits the full amount, credits `amountAfterFee` to `_to` and the fee to the contract (L205–216).",
        "All five fee setters — `FeeStructure` L153–158, `BuySellFee` L249–255, `setScale` L273–279, `setFees` L300–306, `setting` L329–336 — require `new*Fee <= 100`; divisor is 100 (L205, L313, L347).",
        "Modifiers: `onlyAuthorize` accepts D (L190–198); `onlyOwner` and `onlyAuthorized` accept A (L290–298, L360–368); `onlypublic` accepts P (L239–242); `Exchanges` excludes C (L102–105).",
        "Uncapped mint via `_scale` L85–91 → `scaling` L167–170 / `FeesView` L234–237; `_proof` L118–124 → `rewire` L107–111 / `proof` L185–188; `_initiate` L226–232 → `compute` L113–116.",
        "`_transferTo` (L139–146) and `_balanceView` (L172–179) double-credit (2 × `+=`, 2 × events, no supply change).",
        "`buy()` (L308–327) credits tokens to `feeManager` for `msg.value` and keeps the ETH; `sell()` (L344–358) credits the contract and sends no ETH. `LockLPToken()` (L281–282) is empty.",
        "`renounceOwnership` (L267–270) zeroes `owner`; A, D, P and the role chain remain.",
      ],
      "$P_{\\texttt{transfer}}\\equiv\\text{true}$ with $a_{\\text{recv}}=a$; $P_{\\texttt{transferFrom}}\\equiv\\text{true}$ with $a_{\\text{recv}}=a(1-s)$ and $s=\\texttt{sellFee}/100\\in[0,1]$; $s=1\\Rightarrow a_{\\text{recv}}=0$.",
      f"[Math §2]({MATH}#2-fees-taxes-and-the-round-trip-multiplier), [§4]({MATH}#4-supply-invariants-and-the-double-credit-defect), [§5]({MATH}#5-dilution-and-pool-drain-from-hidden-minting)",
      ["Wallet-to-wallet transfer shows 0 % fee; router sell shows `sellFee`.",
       "Scanner: 10 `<= 100` fee-cap hits, D in `onlyAuthorize`, A in two modifiers, P fragment, 2 double-credit helpers.",
       "Set `sellFee = 100` on a fork through each setter and confirm the seller receives zero tokens."],
      ["A", "B", "C", "D", "P"],
      "L37–58, L73–105, L113–198, L200–279, L290–368"),

    F(7, "whitelist-switchable-honeypot", "Whitelist + Switchable Honeypot Mode", "honeypot", "honeypot", "whitelist-switch on&off honeypot mode-honeypot-scanner-detector-proof-token",
      "^0.8.0", 393, "4 — fee switch + exemption", "T2 T4 T5 T6 T7 T9", "Critical", "Honeypot / 100% fee, exempt insiders",
      "Session 6 plus `isFeeExempt`: `transferFrom` skips the fee for exempt senders (L213–215), while `setFeeExempt`/`removeFeeExemptStatus` are `onlyOwner` (L320–330). The separate `sell()` helper ignores the exemption and always charges `sellFee`.",
      [
        "`transfer` (L75–84) fee-free; `transferFrom` (L207–235) charges `amount*sellFee/100` unless `isFeeExempt[_from]`.",
        "`sell()` (L368–382) charges `sellFee` without consulting `isFeeExempt`; `buy()` (L332–351) credits `feeManager`/contract without increasing supply.",
        "Five fee setters with `<= 100` caps: L157–164, L260–266, L284–290, L312–318, L353–360.",
        "Modifiers: `onlyAuthorize` D (L197–205), `onlyOwner`/`onlyAuthorized` A (L301–310, L384–392), `onlypublic` P (L250–253), `Exchanges` ≠ C (L105–108).",
        "Mint paths `_scale` L87–93, `_proof` L121–127, `_initiate` L237–243; double credit `_transferTo` L142–149 and `_balanceView` L177–184.",
        "Chain B → `_mbr` (L96–103) → `_user` (L268–272) → `_mod` (L295–299) → `_adm` (L362–366). `renounceOwnership` L278–281 is cosmetic; `LockLPToken()` L292–293 empty.",
      ],
      "$\\tau_s(h)=0$ if $\\texttt{isFeeExempt}[h]$, else $\\texttt{sellFee}/100\\in[0,1]$ on `transferFrom`; `sell()` always uses $\\texttt{sellFee}/100$.",
      f"[Math §2]({MATH}#2-fees-taxes-and-the-round-trip-multiplier), [§5]({MATH}#5-dilution-and-pool-drain-from-hidden-minting)",
      ["Compare router round-trip from an exempt and a non-exempt address at the same block.",
       "Watch `AddressSetFeeExempt` events and `removeFeeExemptStatus` calls.",
       "Scanner reports D, A, P, B, C and 10 fee-cap hits."],
      ["A", "B", "C", "D", "P"],
      "L75–108, L116–235, L250–368, L384–393"),

    F(8, "v2-blacklist-detector-proof", "Upgraded V2 Blacklist + Detector-Proof Honeypot", "honeypot", "honeypot", "Session 1 - Upgraded V2 Blacklist Honeypot Detector Proof.sol",
      "^0.8.24", 741, "3 — blacklist, UUPS", "T3 T4 T5 T6 T7 T8 T9", "Critical", "Honeypot / UUPS + blacklist",
      "Session 5 logic carried into a UUPS implementation. `initialize` is public with only a private `initialized` bool (L306–320): the first caller becomes owner and receives the whole supply. `_authorizeUpgrade` is `onlyOwner` (L486), a modifier that also accepts A unconditionally.",
      [
        "`initialize(name,symbol,supply,decimals)` L306–320; no constructor, no `_disableInitializers`; first caller wins.",
        "`transfer`/`transferFrom` both call `_transfer` (L508–511, L580–584); `_transfer` (L636–644) rejects blacklisted **sender** with `\"Recipient is Gwei\"`; no fee state.",
        "`zap`/`dezap` (L708–718) are `onlyOwner`; A can call them via the modifier.",
        "Uncapped mint: `_scale` L533–539 via `scaling` (L418–422, `_miu`); `_proof` L655–661 via `proof` (L682–685, A/owner) and `approval` (L562–566, `_adm`); `_dialone` L554–560 via `adjust` (L478–481, P).",
        "Double-credit: `_transferTo` L394–401 (L396/L399) and `_balanceView` L424–431 (L426/L429).",
        "Parallel role root: `setMedium` (L517–524) is hard-coded to D and writes `_miu`. Main chain B → `_mbr` L442–449 → `_user` L462–466 → `_mod` L472–476 → `_adm` L493–497.",
        "`renounceOwnership` L376–379 zeroes `_owner`; A still passes `onlyOwner` and can authorise upgrades.",
      ],
      "$P(h)=[\\neg\\texttt{isBlacklisted}[h]]\\land[h\\ne 0]\\land[t\\ne 0]\\land[v\\le b(h)]$; upgrade predicate is $\\text{caller}=A\\lor(\\text{caller}=owner\\land\\text{caller}\\ne C)$.",
      f"[Math §3]({MATH}#3-sellability-predicate-and-honeypot-classification), [§5]({MATH}#5-dilution-and-pool-drain-from-hidden-minting)",
      ["Review the proxy admin and the first `initialize` transaction; compare implementation bytecode.",
       "Scanner: UUPS + public `initialize` + `renounceOwnership` + D-gated `setMedium` + A in `onlyOwner`.",
       "After renounce, impersonate A on a fork and confirm `onlyOwner` functions still succeed."],
      ["A", "B", "C", "D", "P"],
      "L282–320, L358–435, L442–524, L533–661, L674–729"),

    F(9, "v2-whitelist-switchable", "Upgraded V2 Whitelist + Switchable Honeypot", "honeypot", "honeypot", "Session 2 - Upgraded V2 Whitelist Switch On-Off Honeypot Mode.sol",
      "^0.8.0", 401, "4 — fee switch, UUPS", "T2 T4 T5 T6 T7 T8 T9", "Critical", "Honeypot / UUPS + 100% fee",
      "Session 7 carried into a UUPS implementation. Public `initialize(name,symbol,supply,decimals,feeManager)` (L66–78) is guarded only by a private bool; first caller takes owner, supply and fee-manager control. Fee ceiling remains 100 %.",
      [
        "`initialize` L66–78 sets `owner`, `feeManager`, full supply to caller; no `_disableInitializers`; `_authorizeUpgrade` L80 `onlyOwner` (accepts A).",
        "`transfer` L86–95 fee-free; `transferFrom` L211–239 charges `sellFee` unless `isFeeExempt[_from]`; `sell()` L376–390 ignores the exemption.",
        "Fee setters with `<= 100` caps: `FeeStructure` L166–173, `BuySellFee` L269–275, `setScale` L293–299, `setFees` L320–326, `setting` L361–368.",
        "Mint paths `_scale` L98–104, `_proof` L131–137, `_initiate` L241–247; double-credit `_transferTo` L152–159 and `_balanceView` L187–194.",
        "Chain B → `_mbr` L106–113 → `_user` L281–285 → `_mod` L304–308 → `_adm` L370–374; A and D bypass it.",
        "`renounceOwnership` L287–290 cosmetic; `LockLPToken()` L301–302 empty.",
      ],
      "$\\tau_s(h)=0$ if $\\texttt{isFeeExempt}[h]$, else $\\texttt{sellFee}/100\\in[0,1]$; `sell()` always charges $\\texttt{sellFee}/100$.",
      f"[Math §2]({MATH}#2-fees-taxes-and-the-round-trip-multiplier), [§5]({MATH}#5-dilution-and-pool-drain-from-hidden-minting)",
      ["UUPS initializer front-running check: identify the first caller of `initialize` on the target chain.",
       "Scanner: UUPS, public `initialize`, A/D/B/C/P, 10 fee-cap hits, 2 double-credit helpers.",
       "Router sell at `sellFee = 100` yields zero to the seller."],
      ["A", "B", "C", "D", "P"],
      "L35–78, L86–239, L254–368, L392–400"),

    F(10, "normal-meme-token", "“Normal” Meme Token (not clean)", "token", "token", "normal-meme-pepe-token-non honeypot-code",
      "^0.8.0", 822, "5 — OZ ERC-20 + trade limits", "T3 T4 T5 T6 T7 T9", "Critical", "Backdoored / label false",
      "OpenZeppelin-shaped ERC-20 whose file name says `non honeypot`. `Ownable.onlyOwner` also accepts A (L117–125); there is an uncapped mint surface, a double-credit helper, a hidden parallel config channel (`reviewRules`, L790–795) and blacklist/liquidity gates.",
      [
        "`_beforeTokenTransfer` override (L773–788): rejects blacklisted sender or recipient; while `LiquiduniswapV2Pair == 0`, only transfers involving `owner()` pass; with `tradelimited`, pair→holder buys must stay inside `minHoldingAmount..maxHoldingAmount`.",
        "`_transfer` L534–554 calls the hook; `transfer`/`transferFrom` L398–454. Sells to the pair are not subject to the holding band; buys from the pair are.",
        "`onlyOwner` accepts A **or** stored owner not equal to C (L116–127); `Exchanges` excludes C via `exchanger()` (L338–341, L422–425); `naming` accepts P (L738–741, L798–807).",
        "Mint paths: `proof` (L768–771, A/owner) → `_proof` L556–562; `approval` (L747–751, `_adm`) → `_proof`; `decimal` (L810–813, P) → `_compute` L653–659; `_printbrr` L594–600 is a dead helper.",
        "`viewBalance` (L757–759, P) → `_balanceView` L616–623 credits twice; `transferTo` (L815–817, A/owner) → `_transferTo` L511–518 credits twice.",
        "Role chain: `setMember` (L79–93, B) → `_mbr` → `setUser` L146–149 → `_user` → `setMod` L103–107 → `_mod` → `setAdm` L140–144 → `_adm` → `approval` mint.",
        "`reviewRules` (L790–795, P-only) overwrites pair and limits, duplicating `setPrinciplesRules` (L761–766, owner); `blacklist` L753–755; `renounceOwnership` L136–138 does not remove A or P.",
      ],
      "For a normal transfer: $P=[b_{\\text{from}}\\ge v]\\land[\\texttt{from},\\texttt{to}\\ne 0]\\land[\\neg\\texttt{blacklists[from]}]\\land[\\neg\\texttt{blacklists[to]}]\\land G$, where $G=(\\texttt{pair}=0\\Rightarrow \\texttt{from}=owner\\lor\\texttt{to}=owner)$ and, if `tradelimited` and `from == pair`, $\\texttt{minHolding}\\le b_{\\text{to}}+v\\le\\texttt{maxHolding}$.",
      f"[Math §3]({MATH}#3-sellability-predicate-and-honeypot-classification), [§4]({MATH}#4-supply-invariants-and-the-double-credit-defect), [§5]({MATH}#5-dilution-and-pool-drain-from-hidden-minting)",
      ["Ignore the file name; scanner reports A/B/C, P assembly, A in `onlyOwner`, 2 double-credit helpers, 3 role edges.",
       "Compare calls by owner and by A/P after `renounceOwnership()` on a fork.",
       "Check reported `totalSupply()` against the sum of `Transfer(0,…)` events."],
      ["A", "B", "C", "P"],
      "L79–159, L315–454, L511–623, L731–822"),

    F(11, "ownership-renounce-meme-token", "Ownership-Renounce Meme Token", "token", "token", "ownership renounce-normal-meme-token-non honeypot-code",
      "0.5.16", 588, "Clean — plain BEP-20", "—", "Informational", "No hidden privilege found",
      "Plain BEP-20 with SafeMath and `Ownable`. `onlyOwner` checks only `_owner == _msgSender()` (L304–307); there are no hard-coded addresses, no reachable mint, no lists and no hooks. The constructor sets a fixed supply (L351–359) and `renounceOwnership` (L316–319) is real.",
      [
        "`_transfer` L512–519 checks zero addresses and balance only; `transfer`/`transferFrom` L411–451.",
        "`_mint` L530–536, `_burn` L549–555 and `_burnFrom` L584–587 are internal and have no public callers.",
        "An orphan doc comment at L489–496 describes a `mint` function that does not exist in the code — treated as an unverified claim, not behaviour.",
        "Scanner reports no IOCs, no role chain, no fee caps and no UUPS/initialize.",
      ],
      PLAIN,
      "—",
      ["Verify deployed bytecode matches this source before drawing conclusions about a live token.",
       "Confirm `owner()` is zero if the renounce claim matters."],
      [],
      "L280–359, L411–451, L512–587"),

    F(12, "auto-ownership-renounce-meme-token", "Automatic Ownership-Renounce Meme Token", "token", "token", "automatic ownership renounce-normal-low gas fee-meme-token-non honeypot-code",
      "^0.8.0", 90, "Clean — minimal ERC-20", "—", "Informational", "No hidden privilege found",
      "Minimal fixed-supply ERC-20. The constructor mints 1,000,000 × 10¹⁸ to the deployer and calls `renounceOwnership()` at L29; after construction `owner == address(0)` and no privileged function is reachable.",
      [
        "`onlyOwner` L19–22 requires `owner == msg.sender`, impossible after construction.",
        "`_transfer` L41–54 checks balance before `unchecked` subtract; addition cannot overflow because supply is fixed at $10^{24}$.",
        "`name`, `symbol`, `decimals`, `totalSupply` are storage variables (L5–8), not `constant`; no setters exist.",
        "No mint, burn, fee, list, proxy or hard-coded address in the file.",
      ],
      PLAIN,
      "—",
      ["`owner()` returns zero immediately after deployment.",
       "No mint/fee/list entry points; scanner reports no indicators."],
      [],
      "L4–30, L36–89"),

    F(13, "unlimited-supply-meme-token", "Unlimited Supply Printing Meme Token", "token", "token", "unlimited supply printing-normal-meme-token-non honeypot-code",
      "^0.8.0", 827, "5 — OZ ERC-20 + `print`", "T3 T4 T5 T6 T7 T9", "Critical", "Backdoored / uncapped mint",
      "Session 10 plus public `print(uint256)` (L823–826, `onlyOwner`) calling `_printbrr(msg.sender, amount)` (L594–600), with no cap. All Session 10 controls and hidden roles remain.",
      [
        "`print` L823–826 → `_printbrr` L594–600: `_totalSupply += amount; _balances[account] += amount;` with no upper bound.",
        "Additional mint roots: `proof` L768–771 (A/owner), `approval` L747–751 (`_adm`), `decimal` L810–813 (P).",
        "`viewBalance` L757–759 and `transferTo` L815–817 double-credit via `_balanceView` L616–623 and `_transferTo` L511–518.",
        "Blacklist and liquidity/holding gates in `_beforeTokenTransfer` L773–788 are unchanged from Session 10.",
        "Role chain B → `_mbr` L79–93 → `_user` L146–150 → `_mod` L103–107 → `_adm` L140–144; A and P bypass it.",
        "`renounceOwnership` L136–138 is cosmetic: A remains in `onlyOwner`, P in `naming`.",
      ],
      "Same transfer predicate as Session 10; additionally $\\forall m\\ge 0$ there is a reachable path with $\\Delta S=m$ and $\\Delta b(\\text{caller})=m$.",
      f"[Math §4]({MATH}#4-supply-invariants-and-the-double-credit-defect), [§5]({MATH}#5-dilution-and-pool-drain-from-hidden-minting)",
      ["`print` is public and `onlyOwner`, with no cap or timelock; A can call it even after renounce.",
       "Compare `totalSupply()` with the sum of zero-address `Transfer` events after a `print` call."],
      ["A", "B", "C", "P"],
      "L79–159, L511–623, L731–827"),

    F(14, "v2-unlimited-supply-meme-token", "Upgraded V2 Unlimited Supply Printing Meme Token", "token", "token", "Session 4 - Upgraded V2 Unlimited Supply Printing Meme Token.sol",
      "^0.8.0", 833, "5 — UUPS + `print`", "T3 T4 T5 T6 T7 T8 T9", "Critical", "Backdoored / UUPS + uncapped mint",
      "Session 13 logic on a UUPS base with public `initialize` (L641–652) guarded only by a private bool; first caller wins. `_authorizeUpgrade` (L737) is `onlyOwner`, which accepts A. Note: public `totalSupply` (L620) is a separate counter from ERC-20's private `_totalSupply`, so later mints are not reflected in reported supply.",
      [
        "`initialize` L641–652 sets `owner = msg.sender` (L648) and mints the initial supply (L649); no constructor and no `_disableInitializers`.",
        "`print` L829–832 → `_printbrr` L478–484; `proof` L785–788 → `_proof` L440–446; `approval` L768–772; `decimal` L820–823 → `_compute` L537–543. All uncapped.",
        "Reported `totalSupply` is a public storage variable set only in `initialize` (L620, L646) while mint helpers increase the private ERC-20 `_totalSupply` (L209) — a supply-reporting divergence specific to this session.",
        "`_transferTo` L395–402 and `_balanceView` L500–507 double-credit; `_beforeTokenTransfer` L790–805 keeps S10/S13 blacklist and holding gates.",
        "Role chain B → `_mbr` L659–673 → `_user` L743–747 → `_mod` L690–694 → `_adm` L727–731; A and P are independent roots.",
        "`renounceOwnership` L723–725 zeroes `owner`; A still passes `onlyOwner` (L703–714) and `_authorizeUpgrade` (L737).",
      ],
      "S10/S13 predicate, plus：$\\Delta(\\text{private }\\_totalSupply)=m$ on a mint while public `totalSupply()` may remain unchanged.",
      f"[Math §4]({MATH}#4-supply-invariants-and-the-double-credit-defect), [§5]({MATH}#5-dilution-and-pool-drain-from-hidden-minting)",
      ["Compare `totalSupply()` with the ERC-20 private supply effect inferred from zero-address `Transfer` events.",
       "Identify the initializer caller and proxy admin; scanner reports UUPS, public `initialize`, A/B/C/P and 2 double-credit helpers.",
       "Impersonate A after renounce and confirm upgrade authorisation still passes."],
      ["A", "B", "C", "P"],
      "L12, L209, L395–507, L615–652, L659–832"),

    F(15, "v2-auto-ownership-renounce-meme-token", "Upgraded V2 Automatic Ownership-Renounce Meme Token", "token", "token", "Session 3 - Upgraded V2 Automatic Ownership Renounce Meme Token.sol",
      "^0.8.0", 90, "Clean — minimal ERC-20 (constants)", "—", "Informational", "No hidden privilege found",
      "Session 12 with `name`, `symbol`, `decimals` and `totalSupply` declared `constant` (L5–8). There is no proxy, initializer, mint, list or privileged function despite the `V2` label.",
      [
        "Constructor L24–30 assigns the fixed supply to the deployer and calls `renounceOwnership()` (L29).",
        "`onlyOwner` L19–22 requires `owner == msg.sender`; `renounceOwnership` L86–89 sets `owner = 0`.",
        "`_transfer` L41–54 checks balance before `unchecked` arithmetic; supply is compile-time constant $10^{18}\\times10^{6}$.",
        "No hard-coded addresses, no role chain, no UUPS/initialize; scanner reports no indicators.",
      ],
      PLAIN,
      "—",
      ["Confirm absence of proxy/initializer bytecode on any deployed copy; the `V2` name alone proves nothing.",
       "Reader functions return constants, so storage-read gas differs from Session 12."],
      [],
      "L4–30, L36–89"),
]


def address_rows(addrs):
    if not addrs:
        return ["None found in source or scanner output."]
    out = ["| Label | Literal in source | Decoded address | Role | Evidence |",
           "|---|---|---|---|---|"]
    for tag in addrs:
        literal = ADDR_DEC.get(tag, "(five `uint160` fragments: `0x7addAd09`, `0xcbd98D97`, `0xEC3dA7a0`, `0x088EAdFE`, `0x5801C336`)")
        out.append(f"| **{tag}** | `{literal}` | `{ADDR_HEX[tag]}` | {ADDR_ROLE[tag]} | {ADDR_EVIDENCE[tag]} |")
    return out


def contract_page(s):
    nn = f"{s['n']:02d}"
    fn = f"contracts/{s['sub']}/session-{nn}-{s['slug']}.sol"
    L = [f"# Session {s['n']} — {s['title']}", "",
         "## Identification", "",
         "| Field | Value |", "|---|---|",
         f"| Session | {s['n']} |",
         f"| Source file | `{fn}` |",
         f"| Root artifact | `{s['root']}` |",
         f"| Solidity pragma | `{s['pragma']}` |",
         f"| Lines (incl. comments) | {s['lines']} |",
         f"| Structural family | {s['family']} |",
         f"| Threat classes | {s['tags']} ([taxonomy](../reference/taxonomy.md)) |",
         f"| Severity | **{s['sev']}** |",
         f"| Verdict | {s['verdict']} |", "",
         "## Mechanism", ""] + [f"- {m}" for m in s["mech"]] + [
         "", "## Transfer predicate", "", s["pred"], "",
         "## Equations", "", s["eq"], "",
         "## Detection signals", ""] + [f"- {d}" for d in s["detect"]] + [
         "", "## Hard-coded addresses", ""] + address_rows(s["addresses"]) + [
         "", "## Evidence", "",
         f"Source lines read for this page: {s['evidence']}. Line numbers refer to the `.sol` file in this repository. "
         "Every claim above is tied to those lines or to the [scanner output](../../reports/scanner.txt).", "",
         "## Review guidance", "",
         "Analyse only on a local fork with throw-away keys. Labels, comments and file names are claims, not evidence. "
         "See the [detection playbook](../guides/detection-playbook.md).", "",
         "> Defensive analysis only. Do not deploy this code or present it as safe.", ""]
    return nn, "\n".join(L)


def index_rows():
    out = ["| Session | Solidity | Family | Verdict | Page |", "|---|---|---|---|---|"]
    for s in FACTS:
        nn = f"{s['n']:02d}"
        out.append(f"| {s['n']} | `{s['pragma']}` | {s['family']} | **{s['sev']}** — {s['verdict']} | "
                   f"[S{s['n']}](docs/contracts/session-{nn}-{s['slug']}.md) |")
    return out


README_HEAD = """# Smart-Contract Honeypot Research Handbook

Defensive documentation for the 15 token contracts in [`contracts/`](contracts/), extracted from the attached `out/` archive. The purpose is to help analysts **recognise and detect** hidden privilege and honeypot behaviour from source and from a local fork.

> **Responsible use.** Scope is analysis and detection only. Do not deploy, adapt, configure or market any contract here as safe, and do not use these findings to evade scanners. Work on a local fork with throw-away keys. See [SECURITY](docs/SECURITY.md).

## Key findings

1. **12 of 15 sessions carry a hidden control plane** (S1–S10, S13, S14): decimal or fragment-assembled privileged addresses, a four-step dormant role chain, uncapped mint or balance-assign paths and double-credit helpers. S11, S12 and S15 show no such indicator in source or scanner output.
2. **File names and labels are unreliable.** `normal-meme-pepe-token-non honeypot-code` (S10) and the `unlimited supply printing … non honeypot-code` artifact (S13) are backdoored. `renounceOwnership()` in S5–S10, S13 and S14 is cosmetic: `onlyOwner` also accepts address **A**.
3. **Any reachable uncapped mint approximates a pool drain.** Selling $m$ new tokens removes the fraction $\\frac{\\gamma m}{x+\\gamma m}$ of the quote reserve, which tends to 1 as $m$ grows ([Math §5](docs/reference/math.md#5-dilution-and-pool-drain-from-hidden-minting)).
4. **Sell tests must be path- and state-aware.** Fees are charged in `transferFrom` but not `transfer` (S6–S9); the blacklist (S5, S8, S10, S13, S14) and fee-exempt list (S7, S9) are writable after deployment. A single fresh-address test proves little ([Playbook §4](docs/guides/detection-playbook.md#4-dynamic-test-on-a-fork)).
5. **Compiler version is not a safety signal.** S3 is a `^0.8.19` port of the S1/S2 gate; S8, S9 and S14 are UUPS implementations with a public first-caller-wins `initialize`.
6. **S14 has a second supply-reporting defect:** public `totalSupply` is a separate variable from the ERC-20 private `_totalSupply`, so later mint helpers do not change the reported value ([S14](docs/contracts/session-14-v2-unlimited-supply-meme-token.md)).

## Verified session index

<!-- INDEX:START -->
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
"""

OVERVIEW = """# Documentation Overview

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
"""


def main(root: pathlib.Path) -> None:
    docs = root / "docs" / "contracts"
    docs.mkdir(parents=True, exist_ok=True)
    for s in FACTS:
        nn, page = contract_page(s)
        (docs / f"session-{nn}-{s['slug']}.md").write_text(page, encoding="utf-8")

    readme = root / "README.md"
    text = readme.read_text(encoding="utf-8") if readme.exists() else README_HEAD
    # Keep the static prose but refresh the generated index block.
    if "<!-- INDEX:START -->" in text:
        head, rest = text.split("<!-- INDEX:START -->", 1)
        _, tail = rest.split("<!-- INDEX:END -->", 1)
        text = head + "<!-- INDEX:START -->\n" + "\n".join(index_rows()) + "\n<!-- INDEX:END -->" + tail
        readme.write_text(text, encoding="utf-8")
    else:
        readme.write_text(README_HEAD.replace("<!-- INDEX:START -->\n<!-- INDEX:END -->",
                                              "<!-- INDEX:START -->\n" + "\n".join(index_rows()) + "\n<!-- INDEX:END -->"),
                          encoding="utf-8")
    (root / "docs" / "overview.md").write_text(OVERVIEW, encoding="utf-8")
    print(f"generated {len(FACTS)} contract pages + README index + overview")


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "."))
