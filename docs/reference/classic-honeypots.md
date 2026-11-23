# Catalog of Classic Ethereum Honeypots

> **Evidence status: unverified.** The 14 bait-contract sources (`01_…` – `11_…`, with `a` variants) are **not present in the attached `out/` archive**. The entries below preserve the pre-existing catalog so it is not lost, but no line of those contracts could be re-read here. Only their *arithmetic* was re-checked independently ([Math §6](math.md#6-classic-honeypot-arithmetic)). Treat every mechanism description as an unverified claim until the sources are supplied.

These contracts are teaching material: each looks like an easy way to take Ether, and each is built so the taker loses. They target would-be opportunists. Historical pragma range reported by the earlier docs: 0.4.10 – 0.4.26; several rely on compiler-version behaviour and will not compile unchanged on 0.8.x. **Do not deploy them**, not even locally with funded keys.

## Summary table

| # | File | Contract | Class | One-line mechanism | Severity of pattern |
|---|---|---|---|---|---|
| 01 | `01_unfair_equation.sol` | `MultiplicatorX3` | B1 arithmetic | `this.balance` includes `msg.value` when compared | High |
| 02 | `02_hidden_call.sol` | `Gift_1_ETH` | B2 hidden state | Another contract calls `PassHasBeenSet`, freezing the password | High |
| 02a | `02a_hidden_call.sol` | `G_GAME` | B2 hidden state | Owner-side contract rewrites `responseHash` | High |
| 03 | `03_white_spaces.sol` | `TestToken` | B3 presentation | Long whitespace pushes the owner-only branch off-screen | Medium |
| 04 | `04_storage_overwrite.sol` | `CryptoRoulette` | B3 storage | Uninitialised struct pointer overwrites slot 0 | High |
| 05 | `05_owner_overwrite.sol` | `ICO_Hold` | B3 shadowing | Child redeclares `Owner`; `isOwner()` reads the parent's variable | High |
| 06 | `06_fake_api.sol` | `Private_Bank` + `Log` | B2 external state | Logger reverts, unwinding the reentrant payout | High |
| 07 | `07_early_termination.sol` | `Test1` | B1 integer width | `var` infers `uint8`; loop ends at 255 → pays 255 wei | High |
| 07a | `07a_early_termination.sol` | `For_Test` | B1 integer width | `i*2` wraps in `uint8` → pays 254 wei | High |
| 08 | `08_fake_transfer.sol` | `X2_FLASH` | B4 syntax | `call.value(x)` without `()` sends nothing | Medium |
| 09 | `09_innocent_log.sol` | `firstTest` | B3 delegatecall | "Logging" `delegatecall` rewrites `adr` | High |
| 10 | `10_math_trick.sol` | `RACEFORETH` | B1 series | Halving per-deposit cap sums below the target | Medium |
| 11 | `11_old_compiler.sol` | `DividendDistributorv3` | B4 toolchain | Old compiler drops an empty-string argument | High |

## Detailed entries (pre-existing claims)

### 01 — Unfair Equation (`MultiplicatorX3`)

*Bait*: send at least the contract's balance and get back `balance + value`.
*Claimed mechanism*: in a payable function `this.balance` is read after the call's value is credited, so $v\ge B+v$ is false whenever $B>0$ ([Math §6.1](math.md#61-unfair-equation-01_unfair_equationsol)).
*Detect*: any comparison of `msg.value` to `this.balance` inside a payable function.

### 02 — Hidden Call (`Gift_1_ETH`)

*Bait*: whoever knows the password hash gets the pot; the setter requires 1 ETH.
*Claimed mechanism*: `PassHasBeenSet(hash)` flips the guard flag; a second contract calls it before victims arrive. The call is a message call between contracts and may not appear on an explorer's source page.
*Detect*: inspect internal transactions, not only the contract's own source; ask who can call each state-flipping function and whether anything has.

### 02a — Hidden Call (`G_GAME`)

*Bait*: guess the answer to a question and win the pot.
*Claimed mechanism*: `NewQuestion` lets `questionSender` replace `responseHash`; `require(msg.sender == tx.origin)` stops contracts from probing it. A visible "only EOAs" rule is a hint the author feared simulation.
*Detect*: functions that let the party who funded the pot change the winning condition.

### 03 — White Spaces (`TestToken`)

*Bait*: `withdrawAll()` appears to let anyone take the balance once `total > 0.5 ether`.
*Claimed mechanism*: after a threshold check, a long run of spaces pushes an owner-only branch past the viewport at a particular block height.
*Detect*: run the source through a formatter; search for lines wider than ~200 characters.

### 04 — Storage Overwrite (`CryptoRoulette`)

*Bait*: guess a number 1–10 and take the pot.
*Claimed mechanism*: a struct local declared without `memory` becomes a storage pointer to slot 0, so writing `game.player` overwrites `secretNumber` with a 160-bit address ([Math §6.4](math.md#64-storage-overwrite-04_storage_overwritesol)).
*Detect*: compiler warnings for uninitialised storage pointers; struct locals that are never assigned.

### 05 — Owner Overwrite (`ICO_Hold`)

*Bait*: public `setup()` looks as if anyone can become `Owner` and withdraw deposits.
*Claimed mechanism*: `Ownable` declares `Owner`; `ICO_Hold is Ownable` redeclares it. The inherited `isOwner()` reads the parent's copy while `setup()` writes the child's.
*Detect*: two state variables with the same name in the linearised inheritance chain.

### 06 — Fake API (`Private_Bank` + `Log`)

*Bait*: a bank apparently vulnerable to classic reentrancy.
*Claimed mechanism*: after the external call, a logger at a constructor-supplied address reverts, unwinding the entire transaction including reentrant payouts.
*Detect*: verify what is actually deployed at constructor-supplied addresses, not what the interface suggests.

### 07 / 07a — Early Termination

*Bait*: send ETH and receive double back through a loop.
*Claimed mechanism*: `var` inferred `uint8`; wrap-around ends the loop early. Published payouts: 255 wei (07) and 254 wei (07a) ([Math §6.3](math.md#63-early-termination-by-integer-wrap-07-07a)).
*Detect*: any use of `var` (removed in 0.5.0); loop counters narrower than their bound.

### 08 — Fake Transfer (`X2_FLASH`)

*Bait*: send > 1 ETH, receive the contract's balance.
*Claimed mechanism*: `msg.sender.call.value(this.balance);` evaluates a function object without invoking it; only `…value(x)();` sends.
*Detect*: statements ending in `.value(x);` without trailing call parentheses; unused-expression warnings.

### 09 — Innocent Log (`firstTest`)

*Bait*: send more than the limit and the contract returns the balance.
*Claimed mechanism*: a `delegatecall` to a "logger" runs in this contract's storage and rewrites the winner address slot, so the payout goes to the owner.
*Detect*: any `delegatecall` to an address held in mutable state.

### 10 — Math Trick (`RACEFORETH`)

*Bait*: reach 100 finney of score; the per-deposit cap starts at 50 finney.
*Claimed mechanism*: the cap halves each deposit, so the reachable sum is strictly below the target; exact verified sum is `99,999,999,999,999,979` wei, a 21 wei shortfall ([Math §6.2](math.md#62-math-trick-10_math_tricksol)).
*Detect*: model the reward function's reachable set; if the cap sequence converges below the threshold, the game is unwinnable.

### 11 — Old Compiler (`DividendDistributorv3`)

*Bait*: an "investment" contract with apparently correct withdrawals.
*Claimed mechanism*: under Solidity 0.4.13 an empty string argument is dropped, shifting arguments so a transfer pays the owner rather than the caller. A reversed dividend comparison is also reported.
*Detect*: compile with the exact recorded version and compare bytecode; treat a broad pragma plus a specific old deployment as a red flag.

## Taxonomy cross-reference

| Class | Entries | Playbook step |
|---|---|---|
| B1 Arithmetic and types | 01, 07, 07a, 10 | [Manual review by class](../guides/detection-playbook.md#3-manual-review-checklist-by-class) |
| B2 Hidden or external state | 02, 02a, 06 | [Provenance and bytecode](../guides/detection-playbook.md#1-provenance-and-bytecode) |
| B3 Storage, shadowing, presentation, delegatecall | 03, 04, 05, 09 | [Manual review by class](../guides/detection-playbook.md#3-manual-review-checklist-by-class) |
| B4 Syntax and toolchain | 08, 11 | [Provenance and bytecode](../guides/detection-playbook.md#1-provenance-and-bytecode) |

Class IDs are defined in the [taxonomy](taxonomy.md#classic-bait-classes-b1-b4). Further reading is listed in the [glossary references](glossary.md#references).
