# Catalog of Classic Ethereum Honeypots

Source: the 14 contracts in `Honeypots-on-Blockchain` (`01_…` to `11_…`, with `a` variants of 02 and 07). Each is a *bait* contract: it looks like an easy way to take Ether from the contract, but the code guarantees the taker loses. They target would-be opportunists, which is why they are the standard teaching set for "read the bytecode, not the pitch".

All of them are written for Solidity 0.4.x (`pragma` 0.4.10 – 0.4.26) and several rely on compiler-version behaviour; they do not compile unchanged on 0.8.x. Run them only on a local chain.

## Summary table

| # | File | Contract | Trick class | One-line mechanism | Root cause | Severity of pattern |
|---|---|---|---|---|---|---|
| 01 | `01_unfair_equation.sol` | `MultiplicatorX3` | Arithmetic / EVM semantics | `this.balance` already includes `msg.value` when compared | Condition is unsatisfiable when funds exist | High |
| 02 | `02_hidden_call.sol` | `Gift_1_ETH` | Hidden state change | Another contract calls `PassHasBeenSet`, freezing the password | State mutated by a call not visible on the explorer's source page | High |
| 02a | `02a_hidden_call.sol` | `G_GAME` | Hidden state change | Owner-side contract rewrites `responseHash` | Mutable answer hash | High |
| 03 | `03_white_spaces.sol` | `TestToken` | Presentation | Hundreds of spaces push code off-screen | Code hidden in the same line past the viewport | Medium |
| 04 | `04_storage_overwrite.sol` | `CryptoRoulette` | Storage layout | Uninitialised struct pointer overwrites slot 0 | Local storage pointer defaults to slot 0 | High |
| 05 | `05_owner_overwrite.sol` | `ICO_Hold` | Shadowing | Child redeclares `Owner`, splitting the variable | State-variable shadowing across inheritance | High |
| 06 | `06_fake_api.sol` | `Private_Bank` + `Log` | Reentrancy bait | Logger always reverts, rolling back the reentrant call | Trusting an unverified external contract | High |
| 07 | `07_early_termination.sol` | `Test1` | Integer width | `var i = 1` is `uint8`; loop ends at 255 | Type inference + wrap-around | High |
| 07a | `07a_early_termination.sol` | `For_Test` | Integer width | `i*2` in `uint8` wraps at 128 | Type inference + wrap-around | High |
| 08 | `08_fake_transfer.sol` | `X2_FLASH` | Syntax | `call.value(x)` without `()` sends nothing | Missing call parentheses compile silently | Medium |
| 09 | `09_innocent_log.sol` | `firstTest` | Delegatecall | "Logging" delegatecall rewrites `adr` | `delegatecall` runs in the caller's storage | High |
| 10 | `10_math_trick.sol` | `RACEFORETH` | Series bound | Halving limits sum to < target | Geometric series never reaches $2L_0$ | Medium |
| 11 | `11_old_compiler.sol` | `DividendDistributorv3` | Compiler bug | Old compiler drops an empty-string argument | Compiler 0.4.13 argument shift | High |

## Detailed entries

### 01 — Unfair Equation (`MultiplicatorX3`)

*Bait*: send at least the contract's balance and get back `balance + value`.
*Mechanism*: in a payable function `this.balance` is read **after** the call's value is credited, so the test `msg.value >= this.balance` is $v \ge B + v$, false whenever the prior balance $B>0$ ([Math §6.1](math.md#61-unfair-equation-01_unfair_equationsol)). `Command` and `withdraw` give the deployer a way out.
*Detect*: any comparison of `msg.value` to `this.balance` inside a payable function.

### 02 — Hidden Call (`Gift_1_ETH`)

*Bait*: whoever knows the password hash gets the pot; the setter requires 1 ETH.
*Mechanism*: `PassHasBeenSet(hash)` flips the guard flag when called with the current hash. A second contract calls it, so the guard is closed before any victim can use `SetPass`. The call is a message call between contracts and does not appear in the victim's view of the source.
*Detect*: inspect **internal transactions**, not only the contract's own source; ask who can call each state-flipping function and whether anything has.

### 02a — Hidden Call (`G_GAME`)

*Bait*: guess the answer to a question and win the pot.
*Mechanism*: `NewQuestion` lets `questionSender` replace `responseHash` at any time, via a contract-initiated call invisible on the explorer page. The `require(msg.sender == tx.origin)` stops other contracts from probing it. A visible "only EOAs" rule is a hint the author feared simulation.
*Detect*: functions that let the party who funded the pot change the winning condition.

### 03 — White Spaces (`TestToken`)

*Bait*: `withdrawAll()` appears to let anyone take the balance once `total > 0.5 ether`.
*Mechanism*: after `require(0.5 ether < total);` a very long run of spaces pushes `if (block.number > 5040270) { if (_owner == msg.sender) {…transfer…} else { throw; } }` off the visible line. After that block height only the owner can withdraw and everyone else reverts.
*Detect*: run the source through a formatter; search for lines wider than ~200 characters.

### 04 — Storage Overwrite (`CryptoRoulette`)

*Bait*: guess a number 1–10 and take the pot.
*Mechanism*: `Game game;` declared without `memory` is a pointer to storage slot 0. `game.player = msg.sender` writes the caller's address over `secretNumber`; the guess (≤ 10) can then never equal a 160-bit value ([Math §6.4](math.md#64-storage-overwrite-04_storage_overwritesol)).
*Detect*: compiler warnings for "uninitialized storage pointer"; code that declares a struct local without assigning it.

### 05 — Owner Overwrite (`ICO_Hold`)

*Bait*: `setup()` is public, so it looks as if anyone can make themselves `Owner` and then withdraw other people's deposits.
*Mechanism*: `Ownable` has `address public Owner`; `ICO_Hold is Ownable` re-declares `address public Owner`. `isOwner()` (inherited) reads the parent's variable, while `setup()` writes the child's. The check can never be satisfied by the person who called `setup`.
*Detect*: two state variables with the same name in the linearised inheritance chain.

### 06 — Fake API (`Private_Bank` + `Log`)

*Bait*: a bank that is vulnerable to the classic reentrancy bug (`call.value` before the balance update) so an attacker can drain it.
*Mechanism*: after the external call, `TransferLog.AddMessage(...)` runs. The deployed `Log` at that address is incompatible and reverts, which unwinds the **whole** transaction, including the reentrant payouts. The "vulnerability" is real in the source and non-exploitable on chain.
*Detect*: external-contract addresses supplied at construction; verify what is deployed at them, not what the interface suggests.

### 07 / 07a — Early Termination

*Bait*: send at least 1 (resp. 0.1) ETH and receive double back through a loop.
*Mechanism*: `var` infers `uint8` for small literals; wrap-around ends the loop early and the payout is 255 (resp. 254) wei ([Math §6.3](math.md#63-early-termination-by-integer-wrap-07-07a)).
*Detect*: any use of `var` (removed in 0.5.0); loops whose counter type is narrower than the bound.

### 08 — Fake Transfer (`X2_FLASH`)

*Bait*: send > 1 ETH, receive the contract's balance.
*Mechanism*: `msg.sender.call.value(this.balance);` evaluates to a function object and is never invoked; only `…call.value(this.balance)();` sends. The statement compiles and does nothing. `Kill()` lets the owner reclaim everything.
*Detect*: statements ending in `.value(x);` without a trailing call; unused-expression warnings.

### 09 — Innocent Log (`firstTest`)

*Bait*: send more than the limit and the contract returns the balance.
*Mechanism*: `emails.delegatecall(bytes4(sha3("logEvent()")))` runs the logger's code in *this* contract's storage. The logger writes to the slot of `adr`, replacing the winner address, so `adr.send(this.balance)` pays the owner. `Set()` lets the owner swap the logger.
*Detect*: any `delegatecall` to an address stored in mutable state.

### 10 — Math Trick (`RACEFORETH`)

*Bait*: reach 100 finney of score; per-deposit cap starts at 50 finney "to stop insta-wins".
*Mechanism*: the cap halves each deposit, so the reachable total is a geometric series bounded strictly below 100 finney ([Math §6.2](math.md#62-math-trick-10_math_tricksol)). After three days of inactivity `endRace()` hands the prize to the owner.
*Detect*: model the reward function's reachable set; if the cap sequence converges to a sum below the threshold the game is unwinnable.

### 11 — Old Compiler (`DividendDistributorv3`)

*Bait*: an "investment" contract with dividends and a withdrawal that looks correct.
*Mechanism* (per the file's header and the cited on-chain deployment): under Solidity 0.4.13 an empty string literal `""` passed as a function argument is dropped, shifting the remaining arguments one place, so `loggedTransfer(amount, "", msg.sender, owner)` pays the **owner** rather than the caller. Note also that `calculateDividend()` throws when `sumDividend > lastDividend`, the opposite of the condition it needs, so dividends are never payable.
*Detect*: compile with the *exact* version recorded on the explorer; compare the explorer's bytecode with your own compile; treat `pragma ^0.4.0` with a specific old compiler as a red flag.

## Taxonomy cross-reference

| Class | Entries |
|---|---|
| Arithmetic and types | 01, 07, 07a, 10 |
| Storage and inheritance | 04, 05, 09 |
| Hidden or external state | 02, 02a, 06 |
| Presentation and syntax | 03, 08 |
| Toolchain | 11 |

Each class maps to a review step in the [detection playbook](../guides/detection-playbook.md#3-manual-review-checklist-by-class).

## Further reading (from the source repository)

* Trail of Bits, *not-so-smart-contracts* → `honeypots/`
* thec00n, *smart-contract-honeypots*
* misterch0c, *Solidlity-Vulnerable* → `honeypots/`
* Medium / Hackernoon write-ups linked from the repository README (listed in the [reference index](glossary.md#references)).
