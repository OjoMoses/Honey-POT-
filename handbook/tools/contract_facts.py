"""Single source of truth for the generated contract reference pages.

Every claim rendered into docs/contracts/*.md comes from this table or from
tools/scan_indicators.py output. The table intentionally separates source-level
facts (line numbers, gates, effects) from proposed dynamic tests.

`verdict` values:
  malicious   - source contains a hidden control or accounting trap that can
                block exits or create value ex nihilo.
  clean       - no privileged mint/blacklist/transfer gate was found in scope.
  broken      - malicious or dangerous patterns are present, but the code also
                contains an internal defect that changes the intended exploit
                path (not a safety endorsement).
"""

A = "0x1f490e99657cd08a058c6bb6cd81dd38f59e0e7a"
B = "0x78322d0c5768c9ca370ddfc1d44db0fef3a6e051"
C = "0x0320e7dc23bfae74334d93c20051125ca59e0e7a"
D = "0x63e67a280645edf97880c1df03c8301b151c4668"
P = "0x7addad09cbd98d97ec3da7a0088eadfe5801c336"

COMMON_LIMIT = (
    "No compiler, bytecode, fork, or live deployment was available. "
    "All reachability statements are source-level and conditional on deployment "
    "storage, proxy wiring, and the caller actually holding the named privilege."
)

SESSIONS = [
    {
        "id": "01",
        "slug": "session-01-honeypot-v1",
        "dir": "honeypot",
        "file": "session-01-honeypot-v1.sol",
        "title": "Honeypot V1 — hard-coded owner, overwrite mint, double-credit",
        "classification": "Malicious hidden control",
        "verdict": "malicious",
        "confidence": "High for the source-level control plane; deployment not tested",
        "pragma": "^0.4.26",
        "lines": 284,
        "sha256": "bb95e2a85f2414d95512df164b08c3b4211faa981956cf6a8faec2e4007d2ec3",
        "summary": (
            "A 0.4-era token whose `onlyOwner` modifier checks a hard-coded address, "
            "not the deployer or the public `owner` variable. Two internal helpers "
            "credit a recipient twice, and the owner-gated mint overwrites a balance "
            "instead of adding supply. The visible transfer path works, so a buyer can "
            "receive tokens; the asymmetric privileged paths are the trap."
        ),
        "user_experience": (
            "A buyer can receive tokens through `transfer` and can approve an allowance. "
            "Selling through a pair requires `allow[_from] == true` in `transferFrom`; a "
            "fresh buyer is not automatically allowed. The hidden A key can mint an "
            "arbitrary balance, credit a recipient twice, or toggle the allow map, and "
            "the ordinary `owner` variable does not control any of that."
        ),
        "control": [
            {"actor": "A = " + A, "authority": "Hard-coded `onlyOwner`; survives every ownership assignment", "evidence": "modifier `onlyOwner` at lines 17-24; decimal literal at line 22", "reachability": "Direct if A is controlled by the deployer/operator"},
            {"actor": "B = " + B, "authority": "Starts the role chain by calling `setUsdtPair`", "evidence": "`setUsdtPair` at lines 268-274", "reachability": "B can set `_usdtPair`; then `setUser` is callable by the pair address"},
            {"actor": "P = " + P, "authority": "`onlypublic`: `viewBalance` and `adjust`", "evidence": "`publics()` at lines 190-201; `onlypublic` at lines 148-151", "reachability": "P is assembled from five 32-bit fragments, not discovered from a router"},
            {"actor": "Role chain", "authority": "B → `_usdtPair` → `_user` → `_mod` → `_adm`", "evidence": "setters at lines 153, 213, 238, 268", "reachability": "Each setter trusts the previous role variable; no ownership check on the chain"},
        ],
        "primitives": [
            {"name": "Hard-coded owner", "location": "lines 17-24", "effect": "`require(msg.sender == address(1786...986))`; `owner` is not consulted", "why": "A public `transferOwnership` cannot remove A's power"},
            {"name": "Overwrite mint", "location": "`_mint` lines 218-220; wrapper at 281-283", "effect": "`balances[miner] = value` rather than `+= value`", "why": "Can create or destroy an arbitrary account balance without changing supply"},
            {"name": "Double credit", "location": "`_transferTo` lines 101-108; `_balanceView` lines 117-124", "effect": "Two `balances[to] += amount` operations and two zero-address Transfer events", "why": "Ledger sum grows while `totalSupply` stays fixed"},
            {"name": "Allow-map exit gate", "location": "line 176", "effect": "`transferFrom` requires `allow[_from] == true`", "why": "A buyer can receive but may not be able to sell through a pair"},
            {"name": "No-op tuple", "location": "`viewBalance` line 210", "effect": "`(_to, _amount);` is a tuple expression, not a call", "why": "It does not add a third credit; the double credit is inside the helper"},
        ],
        "paths": [
            {"function": "`transferTo(to, amount)`", "gate": "A (hard-coded `onlyOwner`)", "effect": "Calls `_transferTo`, which credits `to` twice with `amount`; supply unchanged", "evidence": "lines 186-188, 101-108"},
            {"function": "`viewBalance(to, amount)`", "gate": "P (`onlypublic`)", "effect": "Calls `_balanceView`, which credits `to` twice", "evidence": "lines 209-211, 117-124"},
            {"function": "`mint(miner, value)`", "gate": "A", "effect": "`balances[miner] = value`; no `totalSupply` change", "evidence": "lines 281-283, 218-220"},
            {"function": "`adjust(spender, value)`", "gate": "P", "effect": "Overwrites `balances[spender] = value` through `_dialone`", "evidence": "lines 222-225, 264-266"},
            {"function": "`approveAndCall(spender, value)`", "gate": "`_adm`", "effect": "Overwrites `balances[spender] = value`", "evidence": "lines 243-252"},
            {"function": "`transferFrom`", "gate": "allowance + `allow[_from]`", "effect": "Restricted transfer; not a normal BEP-20 exit", "evidence": "lines 168-184"},
        ],
        "invariants": [
            "`totalSupply` is only assigned in the constructor; no path increases it.",
            "`sum(balances)` is not equal to `totalSupply` after `_transferTo`, `_balanceView`, or `mint`.",
            "A's authority is independent of `owner` and is not revoked by `transferOwnership`.",
            "`transferFrom` is gated by `allow[_from]`; `transfer` is not.",
        ],
        "numbers": [
            "Double credit with a=100: recipient +200, supply +0, sum of balances +200.",
            "Overwrite with before=100 and value=500: balance becomes 500, delta +400, supply delta 0.",
            "A = `0x1f49...0e7a`; B = `0x7832...e051`; P = `0x7add...c336`.",
        ],
        "signals": [
            "`require(msg.sender == address(<20+ digit decimal>))` inside a modifier.",
            "Two consecutive `balances[x] += amount` lines in a helper with no subtraction or supply change.",
            "`balances[account] = value` in a function named mint.",
            "`transferFrom` requires a separate boolean allow map.",
            "Five 32-bit constants shifted by 128/96/64/32 and OR-ed into an address.",
        ],
        "tests": [
            "On a fork, call `transferTo(buyer, 100)` from A and read `balanceOf(buyer)` and `totalSupply()`; expect +200 and +0 from this source.",
            "Call `mint(buyer, 500)` from A twice with different values; expect a replacement balance, not accumulation.",
            "Call `transferOwnership(nobody)` from A, then call `mint` again; expect A still authorized.",
            "Buy through the pair, then attempt the sell direction; record whether `allow[buyer]` is false and the transfer reverts.",
        ],
        "limits": [COMMON_LIMIT],
        "errata": [
            "Prior docs call this an `owner`-privileged token and describe legacy pragma vaguely. The modifier ignores the public `owner`; the pragma is `^0.4.26`.",
            "The `owner` variable and `OwnershipTransferred` event are decoys for A's hard-coded authority.",
        ],
        "related": ["02", "03"],
    },
    {
        "id": "02",
        "slug": "session-02-honeypot-v1-2",
        "dir": "honeypot",
        "file": "session-02-honeypot-v1-2.sol",
        "title": "Honeypot V1.2 — same control plane with a cleaner constructor",
        "classification": "Malicious hidden control",
        "verdict": "malicious",
        "confidence": "High for the source-level control plane; deployment not tested",
        "pragma": "^0.4.26",
        "lines": 265,
        "sha256": "a076ae965cd1f7b4fcaff83285d7ebb80b3371c8938b807404b8ef1139429f21",
        "summary": (
            "A near-duplicate of Session 1. `onlyOwner` is still hard-coded to A, "
            "`transferFrom` still requires the separate `allow` map, and `mint` still "
            "overwrites a balance. The constructor syntax is updated and `setMod` / "
            "`setAdm` are present; those changes do not remove the hidden privilege."
        ),
        "user_experience": (
            "The public sale path is ordinary, but the exit path through a pair is "
            "conditional on an allow flag that A, P, or the role chain can set. The "
            "operator can replace a holder's balance or double-credit a chosen account "
            "without increasing the reported supply."
        ),
        "control": [
            {"actor": "A = " + A, "authority": "Hard-coded `onlyOwner`; controls mint, transferTo, addAllow", "evidence": "modifier at lines 103-110; literal at line 107", "reachability": "Direct"},
            {"actor": "B = " + B, "authority": "Can set `_usdtPair`", "evidence": "`setUsdtPair` lines 254-260", "reachability": "B starts the role chain"},
            {"actor": "P = " + P, "authority": "`onlypublic` for viewBalance/adjust/Allowances", "evidence": "`publics` lines 181-192", "reachability": "Assembled literal"},
            {"actor": "Role chain", "authority": "B → `_usdtPair` → `_user` → `_mod` → `_adm`", "evidence": "setters at 149, 204, 229, 254", "reachability": "Trusts prior role variable"},
        ],
        "primitives": [
            {"name": "Hard-coded owner", "location": "lines 103-110", "effect": "`owner` is set in the constructor but never checked by `onlyOwner`", "why": "Ownership transfer is cosmetic with respect to privilege"},
            {"name": "Double credit", "location": "`_transferTo` 76-83; `_balanceView` 122-129", "effect": "Two credits per helper call", "why": "Breaks accounting while supply is fixed"},
            {"name": "Overwrite mint", "location": "`_mint` 209-211; wrapper 262-264", "effect": "Replacement of a balance", "why": "No supply mint is needed to seize value"},
            {"name": "Allow gate", "location": "line 167", "effect": "`require(allow[_from] == true)` in transferFrom", "why": "Exit can be switched off per address"},
            {"name": "Role chain", "location": "lines 149, 204, 229, 254", "effect": "B-controlled chain to `_adm`", "why": "Gives a second operator route to `approveAndCall`/`addAllowance`"},
        ],
        "paths": [
            {"function": "`transferTo`", "gate": "A", "effect": "Double-credits recipient", "evidence": "lines 176-178, 76-83"},
            {"function": "`viewBalance`", "gate": "P", "effect": "Double-credits recipient", "evidence": "lines 200-202, 122-129"},
            {"function": "`mint`", "gate": "A", "effect": "Overwrites balance", "evidence": "lines 262-264, 209-211"},
            {"function": "`adjust` / `approveAndCall`", "gate": "P / `_adm`", "effect": "Overwrites a balance via `_dialone` / `_approvals`", "evidence": "lines 213-216, 236-240, 250-252"},
            {"function": "`transferFrom`", "gate": "allowance + allow map", "effect": "Exit gate for pair transfers", "evidence": "lines 163-174"},
        ],
        "invariants": [
            "`owner` is assigned but is not the effective owner gate.",
            "`totalSupply` is fixed after construction.",
            "`sum(balances)` can exceed or differ from supply after helpers.",
        ],
        "numbers": [
            "Same double-credit arithmetic as Session 1: +2a, supply +0.",
            "Overwrite mint can lower a balance if the supplied value is below the current balance.",
        ],
        "signals": [
            "Decimal address gate in modifier.",
            "Two `+=` credits in `_transferTo` / `_balanceView`.",
            "`require(allow[_from] == true)` in transferFrom.",
            "`owner = msg.sender` present but never used in `onlyOwner`.",
        ],
        "tests": [
            "Verify `owner()` changes after A calls `transferOwnership`, then confirm `mint` authorization is unchanged.",
            "Attempt a sale with `allow[buyer] == false`; expect a revert.",
            "Call `transferTo` and compare event count (two Transfer events) to supply delta (zero).",
        ],
        "limits": [COMMON_LIMIT],
        "errata": [
            "Prior docs describe this as an ownership-controlled token; the effective owner is A, not the `owner` variable.",
            "The presence of `setMod`/`setAdm` does not make the role chain an ownership mechanism.",
        ],
        "related": ["01", "03"],
    },
    {
        "id": "03",
        "slug": "session-03-honeypot-v1-solidity-0.8.19",
        "dir": "honeypot",
        "file": "session-03-honeypot-v1-solidity-0.8.19.sol",
        "title": "Honeypot V1 for Solidity 0.8.19 — compiled-era syntax, same trap",
        "classification": "Malicious hidden control",
        "verdict": "malicious",
        "confidence": "High for source-level control; no compiler run",
        "pragma": "^0.8.19",
        "lines": 409,
        "sha256": "3f2fd120af2f42b813d85ff01bccdfa1380fa1202e85a7d1d4b817974b12edc0",
        "summary": (
            "A whitespace-heavy 0.8.19 port of the V1 family. The hard-coded A modifier, "
            "allow-map exit gate, overwrite mint, and double-credit helpers survive the "
            "port. Checked arithmetic makes the overwrite and double-credit bugs more "
            "visible, not harmless."
        ),
        "user_experience": (
            "The token presents a standard transfer surface and a larger supply. The "
            "operator can still replace any balance or credit a recipient twice; pair "
            "sales depend on the allow map. `transferOwnership` only changes the decoy "
            "`owner` field."
        ),
        "control": [
            {"actor": "A = " + A, "authority": "Hard-coded `onlyOwner`", "evidence": "lines 160-168; literal at 165", "reachability": "Direct"},
            {"actor": "B = " + B, "authority": "Starts role chain through `setUsdtPair`", "evidence": "lines 394-402", "reachability": "Direct"},
            {"actor": "P = " + P, "authority": "`onlypublic` viewBalance/adjust", "evidence": "lines 217-223, 278-296", "reachability": "Assembled literal"},
            {"actor": "Role chain", "authority": "B → `_usdtPair` → `_user` → `_mod` → `_adm`", "evidence": "lines 225, 312, 354, 394", "reachability": "Trusts prior role variable"},
        ],
        "primitives": [
            {"name": "Hard-coded owner", "location": "lines 160-168", "effect": "A, not `owner`", "why": "Renouncing/transferring the visible owner is ineffective"},
            {"name": "Overwrite mint", "location": "321-325, wrapper 404-408", "effect": "`balances[miner] = value`", "why": "Value seizure without supply expansion"},
            {"name": "Double credit", "location": "`_transferTo` 117-128; `_balanceView` 184-196", "effect": "Two credits", "why": "Supply/ledger divergence"},
            {"name": "Allow gate", "location": "line 255", "effect": "`transferFrom` checks `allow[_from]`", "why": "Per-address exit switch"},
            {"name": "0.8 checked arithmetic", "location": "whole file", "effect": "Overflow/underflow normally revert", "why": "Does not fix overwrite or double-credit logic; only removes classic wrap bugs"},
        ],
        "paths": [
            {"function": "`transferTo`", "gate": "A", "effect": "Double credit", "evidence": "lines 271-275, 117-128"},
            {"function": "`viewBalance`", "gate": "P", "effect": "Double credit", "evidence": "lines 306-310, 184-196"},
            {"function": "`mint`", "gate": "A", "effect": "Overwrite", "evidence": "lines 404-408, 321-325"},
            {"function": "`adjust`", "gate": "P", "effect": "Overwrite", "evidence": "lines 327-333, 382-386"},
            {"function": "`approveAndCall`", "gate": "`_adm`", "effect": "Overwrite", "evidence": "lines 364-372, 335-339"},
            {"function": "`transferFrom`", "gate": "allowance + allow map", "effect": "Restricted exit", "evidence": "lines 247-269"},
        ],
        "invariants": [
            "The effective owner gate is an address literal.",
            "`totalSupply` never rises after construction.",
            "The allow map can block pair-mediated exits independently of balance and allowance.",
        ],
        "numbers": [
            "Double credit +2a; overwrite delta = value − old balance.",
            "A = `0x1f49...0e7a`; contract uses 18 decimals only if the constructor is passed 18.",
        ],
        "signals": [
            "Fake-keccak comments wrapped around a decimal address.",
            "`balances[x] = value` in `_mint`.",
            "Two `Transfer(address(0), to, amount)` events in a single helper.",
            "Whitespace-heavy formatting that hides the same control-flow as V1.",
        ],
        "tests": [
            "Compile with the declared 0.8.19 toolchain and compare runtime behavior to Session 1.",
            "Call `transferOwnership` and then `mint`; confirm A still succeeds.",
            "Test a direct `transfer` versus a pair sell (`transferFrom`).",
        ],
        "limits": [COMMON_LIMIT],
        "errata": [
            "Prior docs call this a 'legacy' contract or omit a concrete pragma; source says `^0.8.19`.",
            "Calling it merely 'owner-privileged' misses that A is hard-coded and the visible owner is a decoy.",
        ],
        "related": ["01", "02"],
    },
    {
        "id": "04",
        "slug": "session-04-whitelist-antibot-honeypot",
        "dir": "honeypot",
        "file": "session-04-whitelist-antibot-honeypot.sol",
        "title": "Whitelist anti-bot honeypot — exit only for `canSale` addresses",
        "classification": "Malicious hidden control (whitelist trap)",
        "verdict": "malicious",
        "confidence": "High for the source-level gate; deployment state not tested",
        "pragma": "^0.5.17",
        "lines": 693,
        "sha256": "76e4b479ef07d8f43dd8f23bd6373e3e9d27570d1739fd7d25fe41e057d1fa27",
        "summary": (
            "The conspicuous name is accurate: `ensure` exempts `owner`, `tradeAddress`, "
            "and addresses in `canSale`; everyone else must satisfy `condition`. The "
            "three sale-limit fields are never assigned, so `condition` returns false for "
            "all non-exempt senders. Owner/A/P/_adm can mint balances and whitelist "
            "addresses. This is a whitelist exit trap, not an anti-bot heuristic that "
            "becomes safe after launch."
        ),
        "user_experience": (
            "A buyer can receive tokens when the pair/owner is exempt on the source side. "
            "A normal holder's `transfer` and `transferFrom` both route through "
            "`transferFrom` and `ensure`; without `canSale[holder]`, the call reverts. "
            "The owner and designated trade address can exit. The 'anti-bot' framing is "
            "a cover for an owner-controlled allowlist."
        ),
        "control": [
            {"actor": "Deployer `owner`", "authority": "Exempt in `ensure`; can `approveAndCall` and `transferownership`", "evidence": "lines 409, 616-623, 631-639", "reachability": "Deployment owner; `owner` is private"},
            {"actor": "A = " + A, "authority": "Can overwrite balances/whitelist via `approveAndCall` and set `tradeAddress` via `checkAddress`", "evidence": "lines 614-627, 540-551", "reachability": "Direct hard-coded literal"},
            {"actor": "B = " + B, "authority": "Starts role chain through `setUsdtPair`", "evidence": "lines 371-380, 423-429", "reachability": "Direct"},
            {"actor": "P = " + P, "authority": "`onlypublic`: `transferTo`, `viewAddress`, `adjust`", "evidence": "`publics` 583-601; modifiers 647-653", "reachability": "Assembled literal"},
            {"actor": "`_adm`", "authority": "`approval` overwrites a balance and sets `canSale`", "evidence": "lines 439-447, 382-388", "reachability": "Reached through B → `_usdtPair` → `_user` → `_mod` → `_adm`"},
            {"actor": "`tradeAddress`", "authority": "Exempt from the whitelist gate", "evidence": "line 409; set at 433, 547, 635", "reachability": "Set by P, A, or owner; unset by default"},
        ],
        "primitives": [
            {"name": "Allowlist exit gate", "location": "`ensure` 405-419; `condition` 555-581", "effect": "Owner on either side, `tradeAddress`, or `canSale[from]` bypasses `condition`", "why": "All other sellers revert"},
            {"name": "Never-initialized sale limits", "location": "declarations 608-612", "effect": "`_saleNum`, `_minSale`, `_maxSale` have no writes", "why": "`condition` returns false at line 557 for every non-exempt caller"},
            {"name": "Overwrite credits and whitelist", "location": "`_computing` 363-369; `_approvals` 382-388; `_approvecall` 490-496", "effect": "`balanceOf[spender] = value * 10**decimals`; `canSale[spender] = true`", "why": "Creates balance and exit permission together"},
            {"name": "Double credit", "location": "`_transferTo` 390-401", "effect": "Two credits; called by P-gated `transferTo`", "why": "Supply/ledger divergence"},
            {"name": "Trade address switch", "location": "`viewAddress` 431-437; `checkAddress` 540-551", "effect": "P or A can replace the exempt trade address", "why": "The set of addresses allowed to exit is mutable"},
        ],
        "paths": [
            {"function": "`transfer`", "gate": "public, but calls `transferFrom`", "effect": "Same `ensure` gate as a sale", "evidence": "lines 357-361"},
            {"function": "`transferFrom`", "gate": "allowance if caller is not sender; `ensure`", "effect": "Non-whitelisted holder reverts", "evidence": "lines 451-480"},
            {"function": "`approveAndCall`", "gate": "owner or A", "effect": "Sets a balance and `canSale[spender] = true`", "evidence": "lines 614-627"},
            {"function": "`approval`", "gate": "`_adm`", "effect": "Same overwrite/whitelist helper through `_approvals`", "evidence": "lines 439-447"},
            {"function": "`adjust`", "gate": "P", "effect": "Overwrite/whitelist through `_computing`", "evidence": "lines 482-488, 363-369"},
            {"function": "`transferownership`", "gate": "`owner`", "effect": "Renames/changes `tradeAddress`, not token ownership", "evidence": "lines 631-639"},
        ],
        "invariants": [
            "For every non-exempt `from`, `condition` is false because all three limit variables remain zero.",
            "`canSale` is the only per-address exit permission.",
            "`totalSupply` is set only in the constructor; overwrite credits do not change it.",
            "The `owner` variable is private and is not the same as `tradeAddress`.",
        ],
        "numbers": [
            "`condition`: `_saleNum == 0 && _minSale == 0 && _maxSale == 0` → `false` (line 557).",
            "Overwrite credit: balance becomes `addedValue * 10**18` at `decimals = 18`.",
            "Double credit +2a for P `transferTo`; supply +0.",
        ],
        "signals": [
            "An `ensure` function that returns true for owner/trade address/`canSale` and otherwise requires a condition.",
            "`condition` has an early return false when all three limits are zero.",
            "`canSale[addr] = true` paired with `balanceOf[addr] = …`.",
            "A function named `transferownership` that writes `tradeAddress`.",
            "`transfer` implemented as `transferFrom(msg.sender, to, value)`.",
        ],
        "tests": [
            "On a fork, set the pair as `tradeAddress`; buy, then attempt a sell from a non-whitelisted buyer; expect revert in `condition`.",
            "Set `canSale[buyer] = true` through an authorized path, then retry the sell; record the delta.",
            "Call `transferownership(newAddr)` and confirm the token `owner` is unchanged.",
            "Read `_saleNum`, `_minSale`, `_maxSale` via storage inspection; expect zero and no setter.",
        ],
        "limits": [COMMON_LIMIT, "The file contains an unused ERC20 implementation; do not attribute its `_mint` to the deployed DevToken surface."],
        "errata": [
            "Prior docs say this contract has no pragma; source line 1 is `pragma solidity ^0.5.17;`.",
            "The label 'anti-bot' is misleading: the actual effect is a whitelist exit gate with unset limits, not a bonding-curve or cooldown heuristic.",
            "The inherited-looking `ERC20` contract is not a base of `DevToken`; only the DevToken functions are the token surface.",
        ],
        "related": ["05", "07"],
    },
    {
        "id": "05",
        "slug": "session-05-blacklist-detector-proof-honeypot",
        "dir": "honeypot",
        "file": "session-05-blacklist-detector-proof-honeypot.sol",
        "title": "Blacklist + detector-proof honeypot — hard-coded owner and mint paths",
        "classification": "Malicious hidden control",
        "verdict": "malicious",
        "confidence": "High for source-level control; deployment not tested",
        "pragma": "0.5.16",
        "lines": 741,
        "sha256": "41e48da5aa428d1e57bb642d63fa60bbda4d6dca68710ad15bc8370304df3605",
        "summary": (
            "A BEP-20-shaped token with a blacklist that only checks the sender, a "
            "hard-coded A owner that survives `renounceOwnership`, three public mint "
            "routes, and two double-credit helpers. The renounce function is cosmetic: "
            "it zeroes `_owner` but leaves A's branch in `onlyOwner` intact."
        ),
        "user_experience": (
            "Normal transfers work, but an owner/A/P/role-chain actor can blacklist the "
            "seller, mint a new balance, or double-credit an account. A blacklisted "
            "address can still receive tokens (the recipient is not checked), which can "
            "make the blacklist look inconsistent to a scanner. There is no fee or "
            "automatic liquidity logic."
        ),
        "control": [
            {"actor": "A = " + A, "authority": "Hard-coded `onlyOwner` branch; survives renounce", "evidence": "modifier 314-322; literal 317", "reachability": "Direct"},
            {"actor": "Original `_owner`", "authority": "Second `onlyOwner` branch, excluding C from owner powers", "evidence": "line 320", "reachability": "Deployment owner until renounce"},
            {"actor": "B = " + B, "authority": "Starts role chain through `setMember`", "evidence": "lines 410-416; chain 450, 471, 498", "reachability": "Direct"},
            {"actor": "P = " + P, "authority": "`onlypublic`: `viewBalance`, `symbols`", "evidence": "`publics` 425-436; modifier 394-397", "reachability": "Assembled literal"},
            {"actor": "`_adm`", "authority": "`approval` mints to itself via `_proof`", "evidence": "lines 562-566; `_proof` 655-661", "reachability": "Role chain"},
        ],
        "primitives": [
            {"name": "Hard-coded owner + renounce decoy", "location": "lines 314-322, 331-334", "effect": "`renounceOwnership` clears `_owner`, A remains", "why": "False renounce narrative"},
            {"name": "Sender-only blacklist", "location": "line 637", "effect": "Only `isBlacklisted[sender]` checked; recipient can receive", "why": "Not a standard blacklist and easy to misread"},
            {"name": "Mint paths", "location": "`_calculate` 476-482; `_proof` 655-661; wrappers 544, 562, 682", "effect": "Supply + balance increase", "why": "Unbounded dilution; A, P, and `_adm` routes"},
            {"name": "Double credit", "location": "`_transferTo` 438-445; `_balanceView` 462-469", "effect": "+2a with supply unchanged", "why": "Ledger inflation"},
            {"name": "Role chain", "location": "410, 450, 471, 498", "effect": "B → `_mbr` → `_user` → `_mod` → `_adm`", "why": "Second control path to `approval`"},
        ],
        "paths": [
            {"function": "`proof(amount)`", "gate": "A or `_owner` (excluding C)", "effect": "Mints to caller", "evidence": "682-685, 655-661"},
            {"function": "`symbols(amount)`", "gate": "P", "effect": "Mints to caller through `_calculate`", "evidence": "544-547, 476-482"},
            {"function": "`approval(amount)`", "gate": "`_adm`", "effect": "Mints to `_adm` through `_proof`", "evidence": "562-566"},
            {"function": "`transferTo`", "gate": "A or `_owner`", "effect": "Double-credits recipient", "evidence": "516-518, 438-445"},
            {"function": "`viewBalance`", "gate": "P", "effect": "Double-credits recipient", "evidence": "531-533, 462-469"},
            {"function": "`zap` / `dezap`", "gate": "A or `_owner`", "effect": "Sets/clears sender blacklist", "evidence": "708-718"},
        ],
        "invariants": [
            "A remains authorized after `renounceOwnership()`.",
            "The blacklist does not prevent receiving.",
            "`totalSupply` can grow without a supply cap.",
            "`transferTo` and `viewBalance` increase the sum of balances by more than any supply change.",
        ],
        "numbers": [
            "Mint `proof(1000)` adds 1000 to supply and caller balance.",
            "Double credit `transferTo(buyer, 100)` adds 200 to buyer, 0 to supply.",
            "A = `0x1f49...0e7a`; P = `0x7add...c336`.",
        ],
        "signals": [
            "`onlyOwner` with `msg.sender == address(<literal>) || msg.sender == _owner && ...`.",
            "`renounceOwnership` sets `_owner = address(0)` but not the literal branch.",
            "`require(!isBlacklisted[sender])` with no recipient check.",
            "Internal mint helper called from multiple public wrappers.",
            "`_transferTo` or `_balanceView` contains two `+=` operations.",
        ],
        "tests": [
            "Call `proof(1e18)` from A after `renounceOwnership()`; expect success.",
            "Blacklist a holder, then have a third party send tokens to that holder; expect success.",
            "Call `symbols` from P and verify supply/balance delta.",
            "Call `transferTo` and compare logs to supply.",
        ],
        "limits": [COMMON_LIMIT, "No fee is charged despite the name 'detector-proof'; the detector-proof aspect is the hidden privilege, not a fee mechanism."],
        "errata": [
            "Prior docs imply renounce removes owner powers; it only removes the stored `_owner` branch.",
            "Prior docs do not mention the P-only mint `symbols` or the `_adm` mint `approval`.",
            "The blacklist is sender-only; calling it a standard blacklist overstates its scope.",
        ],
        "related": ["08", "06"],
    },
    {
        "id": "06",
        "slug": "session-06-switchable-honeypot-mode",
        "dir": "honeypot",
        "file": "session-06-switchable-honeypot-mode.sol",
        "title": "Switchable mode — token-side fees, ETH sink, and hidden minters",
        "classification": "Malicious hidden control and broken fee accounting",
        "verdict": "broken",
        "confidence": "High for source-level effects; no execution",
        "pragma": "^0.8.0",
        "lines": 369,
        "sha256": "627bedcac0ac2cbe1271d1a9bd2abe1ba4e424ffc5b96c4f243139f0bcd32eff",
        "summary": (
            "The name suggests a switch between normal and honeypot modes, but the code "
            "has no whitelist or mode enum. It has configurable fees up to 100%, a "
            "`transferFrom` tax that always reads `sellFee`, a `buy()` payable function "
            "that credits balances without increasing supply and keeps ETH, a `sell()` "
            "that sends tokens to the contract without paying ETH, and several mint "
            "routes. A `renounceOwnership` call leaves A's hard-coded branch intact."
        ),
        "user_experience": (
            "Plain `transfer` is free; pair-mediated `transferFrom` can be taxed at "
            "`sellFee` up to 100%. `buy()` and `sell()` are custom functions that do not "
            "perform an AMM trade. Calling `buy()` sends ETH to the contract and credits "
            "tokens to `feeManager`/the contract; calling `sell()` moves tokens to the "
            "contract but has no ETH payout. The operator can mint through several "
            "role-gated paths."
        ),
        "control": [
            {"actor": "A = " + A, "authority": "`onlyAuthorized` and `onlyOwner` branch; fee setting and mints", "evidence": "modifiers 190-198, 290-298, 360-368; literal 193/293/363", "reachability": "Direct"},
            {"actor": "D = " + D, "authority": "`onlyAuthorize` branch; `transferTo`, `FeesView`, `BuySellFee`", "evidence": "modifier 190-198; literal 193", "reachability": "Direct hard-coded literal"},
            {"actor": "B = " + B, "authority": "Starts role chain through `setMember`", "evidence": "93-100; chain 257, 284, 338", "reachability": "Direct"},
            {"actor": "P = " + P, "authority": "`onlypublic`: `viewBalance`, `compute`, `FeeStructure`", "evidence": "`publics` 126-137; modifier 239-242", "reachability": "Assembled literal"},
            {"actor": "`_adm`", "authority": "Can mint via `rewire`; can set fees via `setting`", "evidence": "107-111, 329-336", "reachability": "Role chain"},
        ],
        "primitives": [
            {"name": "Fee cap 100", "location": "154-155, 250-251, 274-275, 301-302, 331-332", "effect": "100% is accepted", "why": "A 100% tax can confiscate the entire transfer amount"},
            {"name": "Token-side tax", "location": "`transferFrom` 200-224", "effect": "Fee is credited to the token contract in tokens; supply unchanged", "why": "Tax is not paid in ETH or routed to a liquidity pool"},
            {"name": "ETH sink buy", "location": "`buy` 308-327", "effect": "Credits `feeManager` and contract with ETH base units; no supply increase; ETH stays", "why": "Accounting inflation plus unrecoverable ETH"},
            {"name": "No-payout sell", "location": "`sell` 344-358", "effect": "Deducts user tokens and credits contract; no ETH transfer", "why": "Not a sale; it is a token sink"},
            {"name": "Hidden mint routes", "location": "`_scale` 85-91; `_proof` 118-124; `_initiate` 226-232", "effect": "Supply + balance mint methods exposed through role gates", "why": "Dilution and arbitrary balance creation"},
            {"name": "Cosmetic renounce", "location": "267-270", "effect": "Clears `owner` but A remains in both privilege modifiers", "why": "False safety signal"},
        ],
        "paths": [
            {"function": "`FeeStructure` / `setScale` / `setFees` / `BuySellFee` / `setting`", "gate": "P / A / D / `_adm`", "effect": "Set buyFee/sellFee up to 100", "evidence": "153-158, 249-255, 273-279, 300-306, 329-336"},
            {"function": "`transferFrom`", "gate": "allowance; fee = sellFee", "effect": "Taxed transfer to recipient; fee to contract", "evidence": "200-224"},
            {"function": "`buy()`", "gate": "public payable", "effect": "Credits new balances; no supply change; ETH retained", "evidence": "308-327"},
            {"function": "`sell(amount)`", "gate": "public", "effect": "Moves tokens to contract; no ETH output", "evidence": "344-358"},
            {"function": "`proof`, `rewire`, `scaling`, `FeesView`, `compute`", "gate": "A / `_adm` / A-or-D / P", "effect": "Mint paths", "evidence": "185-188, 107-111, 167-170, 234-237, 113-116"},
            {"function": "`LockLPToken`", "gate": "A or owner", "effect": "Empty body; does nothing", "evidence": "281-282"},
        ],
        "invariants": [
            "`buy()` increases the sum of balances without changing totalSupply.",
            "`sell()` has no ETH transfer.",
            "`transferFrom` taxes every call by `sellFee`, including calls that are not a DEX sell.",
            "A remains privileged after `renounceOwnership`.",
        ],
        "numbers": [
            "buy 1 ETH at 5%: +0.95e18 to `feeManager`, +0.05e18 to contract, supply +0, ETH +1e18 to contract.",
            "sell 1000 tokens at 10%: user −1000, contract +900 +100, ETH 0.",
            "100% sell: net recipient 0; `_amount.sub(fee)` is 0, not a revert.",
        ],
        "signals": [
            "`require(newSellFee <= 100)` (not `< 100`).",
            "`buy()`/`sell()` naming on a token with no router interaction.",
            "`balanceOf[feeManager] += amount` without a supply increase.",
            "`LockLPToken()` with an empty body.",
            "Hard-coded A/D branches alongside a stored `owner`.",
        ],
        "tests": [
            "Fork test: call `buy()` with 1 ETH from a fresh account; check ETH balance, token balance, supply, and event count.",
            "Set sellFee=100, then call `transferFrom`; verify recipient receives zero and supply is unchanged.",
            "Call `renounceOwnership`, then `mint`/`setFees` from A; expect success.",
            "Check whether any function sends ETH; source suggests none.",
        ],
        "limits": [COMMON_LIMIT, "The name 'switchable honeypot mode' is not backed by a mode switch in source; only fee setters and role gates exist."],
        "errata": [
            "Prior docs describe a whitelist/mode switch; no whitelist mapping or mode enum exists. Fees are the only switch.",
            "The fee is charged in tokens by `transferFrom`, not as an ETH buy/sell tax routed to a pair.",
            "`LockLPToken` is a no-op; it does not lock liquidity.",
        ],
        "related": ["07", "09"],
    },
    {
        "id": "07",
        "slug": "session-07-whitelist-switchable-honeypot",
        "dir": "honeypot",
        "file": "session-07-whitelist-switchable-honeypot.sol",
        "title": "Whitelist-switchable honeypot — fee exemptions, not an exit whitelist",
        "classification": "Malicious hidden control and broken fee accounting",
        "verdict": "broken",
        "confidence": "High for source-level effects; no execution",
        "pragma": "^0.8.0",
        "lines": 393,
        "sha256": "ed97be16537db1921277290fa82a5e2cc86a218e31b87c9ed28f842ad3111de6",
        "summary": (
            "Session 6 plus an `isFeeExempt` mapping. The word 'whitelist' refers only "
            "to fee exemption, not to a transfer allowlist or an anti-bot exit gate. "
            "The tax still reads `sellFee` in every `transferFrom`; the owner/A still "
            "survive renounce; and the custom buy/sell functions still create ledger "
            "credits without a matching supply or ETH payout."
        ),
        "user_experience": (
            "A fee-exempt address avoids the `sellFee` deduction in `transferFrom`; a "
            "non-exempt holder pays it. This is not a general whitelist that controls "
            "who can trade. The public `transfer` path is free, while pair-mediated "
            "transfers can be taxed up to 100%."
        ),
        "control": [
            {"actor": "A = " + A, "authority": "`onlyOwner` / `onlyAuthorized`; fee and exemption control", "evidence": "modifiers 301-310, 384-392; literal 304/387", "reachability": "Direct"},
            {"actor": "D = " + D, "authority": "`onlyAuthorize`: transferTo, FeesView, BuySellFee", "evidence": "modifier 197-205; literal 200", "reachability": "Direct"},
            {"actor": "B = " + B, "authority": "Starts role chain", "evidence": "96-103; chain 268, 295, 362", "reachability": "Direct"},
            {"actor": "P = " + P, "authority": "`onlypublic`: viewBalance, compute, FeeStructure", "evidence": "129-140, 250-253", "reachability": "Assembled literal"},
            {"actor": "Fee-exempt set", "authority": "`isFeeExempt[addr]`; owner can add/remove", "evidence": "47, 320-330", "reachability": "Not a trading allowlist"},
        ],
        "primitives": [
            {"name": "Fee exemption, not whitelist", "location": "47, 212-215, 320-330", "effect": "Skips fee only; no transfer gate", "why": "The contract name overstates the mechanism"},
            {"name": "Fee cap 100", "location": "158-159, 261-262, 285-286, 313-314, 355-356", "effect": "100% tax accepted", "why": "Recipient can receive zero"},
            {"name": "Token-side tax", "location": "207-235", "effect": "Fee credited to contract; supply unchanged", "why": "No ETH or LP routing"},
            {"name": "ETH sink / no-payout functions", "location": "buy 332-351; sell 368-382", "effect": "Same Session 6 accounting", "why": "Not AMM functions"},
            {"name": "Hidden mint routes", "location": "87-93, 121-127, 237-243", "effect": "Role-gated supply increase", "why": "Dilution"},
            {"name": "Cosmetic renounce", "location": "278-281", "effect": "A remains", "why": "False renounce"},
        ],
        "paths": [
            {"function": "`setFeeExempt` / `removeFeeExemptStatus`", "gate": "A or owner", "effect": "Toggles fee exemption only", "evidence": "320-330"},
            {"function": "`transferFrom`", "gate": "allowance; fee if not exempt", "effect": "Taxed transfer; fee to contract", "evidence": "207-235"},
            {"function": "`buy` / `sell`", "gate": "public payable / public", "effect": "Ledger credit or token sink; no ETH payout", "evidence": "332-351, 368-382"},
            {"function": "`proof`, `rewire`, `scaling`, `FeesView`, `compute`", "gate": "A / `_adm` / A-or-D / P", "effect": "Mint paths", "evidence": "192-195, 110-114, 172-175, 245-248, 116-119"},
            {"function": "`LockLPToken`", "gate": "A or owner", "effect": "Empty", "evidence": "292-293"},
        ],
        "invariants": [
            "Fee exemption does not imply transfer permission.",
            "`buyFee` is set but never used by `transferFrom`; only `sellFee` is applied.",
            "A remains privileged after renounce.",
            "The token contract accumulates fee tokens with no distribution path.",
        ],
        "numbers": [
            "5% fee on 1000 = 50; recipient gets 950, contract gets 50.",
            "Fee-exempt 1000 transfer = 1000 to recipient, 0 to contract.",
            "100% fee: recipient gets 0; no revert.",
        ],
        "signals": [
            "`isFeeExempt` mapping used only inside `transferFrom`.",
            "No address-list check in `transfer`.",
            "`buyFee` assigned but only `sellFee` read in transferFrom.",
            "`LockLPToken` no-op.",
            "Empty/renamed role chain to `_adm`.",
        ],
        "tests": [
            "Compare `transfer` and `transferFrom` for the same amount and holders.",
            "Set a holder exempt; confirm no fee but no other permission change.",
            "Set sellFee=100 and verify the recipient receives zero.",
            "Check that buyFee does not affect `transferFrom`.",
        ],
        "limits": [COMMON_LIMIT, "No whitelist mode switch exists despite the filename; the only address list is fee exemption."],
        "errata": [
            "Prior docs describe a 'whitelist switchable' mode; source has only fee exemption and fee rates.",
            "The filename implies a trading allowlist, but `transfer` is unrestricted.",
            "The fee is token-denominated, not an ETH buy/sell tax.",
        ],
        "related": ["06", "09"],
    },
    {
        "id": "08",
        "slug": "session-08-v2-blacklist-detector-proof",
        "dir": "honeypot",
        "file": "session-08-v2-blacklist-detector-proof.sol",
        "title": "V2 blacklist honeypot — UUPS proxy, public initialize, D-gated mint",
        "classification": "Malicious hidden control (upgradeable)",
        "verdict": "malicious",
        "confidence": "High for source-level control; proxy deployment not tested",
        "pragma": "^0.8.24",
        "lines": 741,
        "sha256": "13ab33b605c4b0e023ba07334f1b2ea6abe9fb27175daacee2e2a8d0144a285a",
        "summary": (
            "A UUPS port of the blacklist family. `initialize` is public and the "
            "implementation does not call `_disableInitializers`; ownership is A-or-"
            "stored-owner, and A survives renounce. The blacklist checks only the sender. "
            "A new D-gated `setMedium` path feeds `scaling`, which mints to the caller. "
            "P can mint through `adjust`, and `_adm` through `approval`."
        ),
        "user_experience": (
            "A proxy can be initialized by whoever calls first if deployment is not "
            "atomic. The owner/A can blacklist sellers and mint; P and `_adm` have "
            "additional mint routes. A blacklisted address can still receive. The "
            "upgrade key is the same onlyOwner gate, so A can replace the implementation."
        ),
        "control": [
            {"actor": "A = " + A, "authority": "`onlyOwner`, including `_authorizeUpgrade`; mint/blacklist/transferTo", "evidence": "modifier 358-367; literal 361; upgrade 486", "reachability": "Direct; can upgrade the proxy"},
            {"actor": "Original `_owner`", "authority": "Second branch of `onlyOwner`, excluding C", "evidence": "line 364", "reachability": "Initialize caller until renounce"},
            {"actor": "D = " + D, "authority": "`setMedium`; then `scaling` mints for `_miu`", "evidence": "517-524, 418-422, 533-539", "reachability": "Direct; D can set itself as `_miu`"},
            {"actor": "B = " + B, "authority": "Starts role chain", "evidence": "442-449; chain 462, 472, 493", "reachability": "Direct"},
            {"actor": "P = " + P, "authority": "`onlypublic`: `viewBalance` double credit, `adjust` mint", "evidence": "381-392, 513-515, 478-481", "reachability": "Assembled literal"},
            {"actor": "`_adm`", "authority": "`approval` mint", "evidence": "562-566", "reachability": "Role chain"},
        ],
        "primitives": [
            {"name": "Public initialize", "location": "306-320", "effect": "First caller becomes `_owner` and receives supply; no `_disableInitializers`", "why": "Deployment race / implementation initialization"},
            {"name": "Hard-coded owner + renounce", "location": "358-367, 376-379", "effect": "A survives renounce", "why": "False renounce"},
            {"name": "Upgradeable", "location": "486", "effect": "`_authorizeUpgrade` is onlyOwner", "why": "A can change code, not just parameters"},
            {"name": "D-gated mint", "location": "517-524, 418-422, 533-539", "effect": "D sets `_miu`; `_miu` mints via `scaling`", "why": "Fourth mint authority beyond owner/P/_adm"},
            {"name": "Sender-only blacklist", "location": "636-644", "effect": "Recipient not checked", "why": "Incomplete freeze semantics"},
            {"name": "Double credit", "location": "394-401, 424-431", "effect": "+2a, supply +0", "why": "Ledger inflation"},
        ],
        "paths": [
            {"function": "`initialize`", "gate": "public, `!initialized`", "effect": "Sets owner, supply, balance; no disable", "evidence": "306-320"},
            {"function": "`setMedium` → `scaling`", "gate": "D then `_miu`", "effect": "Mint to `_miu`", "evidence": "517-524, 418-422, 533-539"},
            {"function": "`proof`", "gate": "A or `_owner`", "effect": "Mint to caller", "evidence": "682-685, 655-661"},
            {"function": "`adjust`", "gate": "P", "effect": "Mint to caller", "evidence": "478-481, 554-560"},
            {"function": "`approval`", "gate": "`_adm`", "effect": "Mint to `_adm`", "evidence": "562-566"},
            {"function": "`transferTo` / `viewBalance`", "gate": "A-or-owner / P", "effect": "Double credit", "evidence": "433-435, 513-515, 394-401, 424-431"},
            {"function": "`zap` / `dezap`", "gate": "A or `_owner`", "effect": "Sender blacklist", "evidence": "708-718"},
        ],
        "invariants": [
            "`initialized` is a custom bool; the implementation can be initialized once.",
            "A remains an owner and upgrade authority after renounce.",
            "The blacklist does not block receiving.",
            "`scaling` is gated by `_miu`, but D controls `_miu`.",
        ],
        "numbers": [
            "`initialize(T)` sets supply T and balance T; no double mint in this version.",
            "`scaling(1000)` adds 1000 to supply and caller balance.",
            "Double credit +2a; supply +0.",
        ],
        "signals": [
            "UUPS import plus a public `initialize` with no `_disableInitializers` call.",
            "`_authorizeUpgrade` behind an onlyOwner gate that includes a literal.",
            "`setMedium` literal gate leading to `scaling`.",
            "`onlyOwner` is `(literal || _owner && msg.sender != exchange())`.",
            "Sender-only blacklist require.",
        ],
        "tests": [
            "Deploy implementation and proxy on a fork; attempt to initialize the implementation from a non-deployer.",
            "Race a second initialize on a freshly deployed proxy; record whether the first caller wins.",
            "Call `setMedium(D)` as D, then `scaling` as D; verify mint.",
            "Renounce as `_owner`, then call `proof` from A.",
        ],
        "limits": [COMMON_LIMIT, "Upgradeability and initializer race findings are source-level; actual proxy admin/storage layout was not exercised."],
        "errata": [
            "Prior docs call this 'V2 blacklist detector-proof' without noting UUPS upgrade authority or public initialize.",
            "The blacklist is not bidirectional.",
            "The D/`_miu` mint chain is not mentioned in prior docs.",
        ],
        "related": ["05", "09", "14"],
    },
    {
        "id": "09",
        "slug": "session-09-v2-whitelist-switchable",
        "dir": "honeypot",
        "file": "session-09-v2-whitelist-switchable.sol",
        "title": "V2 whitelist-switchable — UUPS fee token with hidden minters",
        "classification": "Malicious hidden control (upgradeable)",
        "verdict": "broken",
        "confidence": "High for source-level effects; proxy deployment not tested",
        "pragma": "^0.8.0",
        "lines": 401,
        "sha256": "69857f43530e00b5187e4d4cbcdb23d397e21d3c04dcb1e2b71d72deedacd1dd",
        "summary": (
            "A UUPS version of the fee-switch family. It has public initialize with no "
            "initializer disable, 100%-cap fee setters, fee exemption, token-side tax, "
            "custom buy/sell functions with no ETH payout, and A/D/P/_adm mint routes. "
            "There is no whitelist or mode switch beyond fee exemption."
        ),
        "user_experience": (
            "`transfer` is free; `transferFrom` can tax at `sellFee` up to 100%. Exempt "
            "addresses avoid the tax. The custom `buy`/`sell` functions are not AMM "
            "operations and leave ETH/tokens in the contract. If proxy initialization is "
            "not atomic, the first caller can become owner and receive supply."
        ),
        "control": [
            {"actor": "A = " + A, "authority": "`onlyOwner`/`onlyAuthorized`; upgrade authority", "evidence": "310-318, 392-400, 80; literal 313/395", "reachability": "Direct; can upgrade"},
            {"actor": "Original `owner`", "authority": "Second branch; excludes C", "evidence": "316, 398", "reachability": "Initialize caller"},
            {"actor": "D = " + D, "authority": "`onlyAuthorize`: transferTo, FeesView, BuySellFee", "evidence": "201-209; literal 204", "reachability": "Direct"},
            {"actor": "B = " + B, "authority": "Starts role chain", "evidence": "106-113; chain 281, 304, 370", "reachability": "Direct"},
            {"actor": "P = " + P, "authority": "`onlypublic`: viewBalance, compute, FeeStructure", "evidence": "139-150, 254-257", "reachability": "Assembled literal"},
            {"actor": "`_adm`", "authority": "`rewire` mint; fee setting", "evidence": "120-124, 361-368", "reachability": "Role chain"},
        ],
        "primitives": [
            {"name": "Public initialize", "location": "66-78", "effect": "No `_disableInitializers`; first caller owns proxy/implementation", "why": "Deployment race"},
            {"name": "Fee cap 100", "location": "167-168, 270-271, 294-295, 321-322, 363-364", "effect": "100% tax", "why": "Full confiscation"},
            {"name": "Fee exemption", "location": "45, 216-218, 328-337", "effect": "Skips `sellFee` only", "why": "Not a trading whitelist"},
            {"name": "Token-side tax", "location": "211-239", "effect": "Fee to contract; supply unchanged", "why": "No ETH payout"},
            {"name": "ETH sink / no payout", "location": "340-359, 376-389", "effect": "Buy credits; sell sinks; no ETH transfer", "why": "Not a sale"},
            {"name": "Mint routes", "location": "98-104, 131-137, 241-247, 249-252", "effect": "P/A/`_adm` can inflate supply", "why": "Dilution"},
        ],
        "paths": [
            {"function": "`initialize`", "gate": "public, `!initialized`", "effect": "Sets owner/feeManager/supply/balance", "evidence": "66-78"},
            {"function": "`transferFrom`", "gate": "allowance; exempt check; sellFee", "effect": "Taxed transfer", "evidence": "211-239"},
            {"function": "`buy` / `sell`", "gate": "public payable / public", "effect": "Ledger credit / token sink", "evidence": "340-359, 376-389"},
            {"function": "`proof`, `rewire`, `scaling`, `FeesView`, `compute`", "gate": "A-or-owner / `_adm` / A-or-D / P", "effect": "Mint", "evidence": "264-267, 120-124, 182-185, 249-252, 126-129"},
            {"function": "`setFeeExempt`", "gate": "A or owner", "effect": "Fee waiver", "evidence": "328-337"},
            {"function": "`LockLPToken`", "gate": "A or owner", "effect": "Empty", "evidence": "301-302"},
        ],
        "invariants": [
            "`buyFee` is set but unused by `transferFrom`; only `sellFee` applies.",
            "Fee exemption is not a transfer allowlist.",
            "A remains owner after renounce and can upgrade.",
            "`buy`/`sell` do not pay ETH.",
        ],
        "numbers": [
            "1 ETH buy at 5%: 0.95e18 feeManager, 0.05e18 contract, supply +0, ETH retained.",
            "1000 transfer at 100%: recipient 0, contract 1000, no revert.",
            "5%/10% round-trip leaves 85.5% before price movement.",
        ],
        "signals": [
            "`initialize` public with no `_disableInitializers`.",
            "`_authorizeUpgrade` uses an onlyOwner with a literal branch.",
            "100% fee cap and only `sellFee` in transferFrom.",
            "`LockLPToken` empty; custom buy/sell with no ETH send.",
            "P and `_adm` mint wrappers.",
        ],
        "tests": [
            "Initialize a proxy twice in a fork; verify first-caller ownership.",
            "Set sellFee=100 and confirm zero recipient amount.",
            "Call `buy()` with 1 ETH and verify no supply change.",
            "Renounce owner, then call `_authorizeUpgrade`/`proof` from A.",
        ],
        "limits": [COMMON_LIMIT, "Proxy storage layout and upgrade execution were not tested; no `_disableInitializers` is visible in source."],
        "errata": [
            "Prior docs describe a whitelist switch; source only has fee exemption and fee rates.",
            "Prior docs omit the public initializer and upgrade authority.",
            "The fee is token-denominated, not an ETH tax routed to the pair.",
        ],
        "related": ["06", "07", "08"],
    },
    {
        "id": "10",
        "slug": "session-10-normal-meme-token",
        "dir": "token",
        "file": "session-10-normal-meme-token.sol",
        "title": "“Normal” meme token — full hidden control plane under an OZ-looking shell",
        "classification": "Malicious hidden control (mislabeled as normal)",
        "verdict": "malicious",
        "confidence": "High for source-level control; deployment not tested",
        "pragma": "^0.8.0",
        "lines": 822,
        "sha256": "e95b55d4259f1561bf605e82c750b4c5b8078b62b0e2e82bef857f0c49fda32a",
        "summary": (
            "Despite the filename and prior 'non-honeypot' labels, this is an OpenZeppelin-"
            "shaped ERC-20 with a hard-coded A owner, a B-started role chain to `_adm`, "
            "and four extra mint/credit routes: `proof`, `approval`, `decimal`, and "
            "`transferTo`/`viewBalance`. `reviewRules` is P-gated and can change the pair "
            "and holding limits. `renounceOwnership` leaves A in control."
        ),
        "user_experience": (
            "Before a pair is set, only the owner can move tokens. After the owner/P sets "
            "a pair, ordinary transfers work subject to blacklist and optional min/max "
            "holding limits on buys. P can silently change those rules, and privileged "
            "actors can mint or double-credit balances at will. The token is not a normal "
            "fixed-supply meme token."
        ),
        "control": [
            {"actor": "A = " + A, "authority": "Hard-coded onlyOwner; mint/blacklist/rules/transferTo", "evidence": "modifier 116-127; literal 122", "reachability": "Direct; survives renounce"},
            {"actor": "B = " + B, "authority": "Starts role chain via `setMember`", "evidence": "79-93; chain 146, 103, 140", "reachability": "Direct"},
            {"actor": "P = " + P, "authority": "`naming`: `viewBalance`, `decimal`, `reviewRules`", "evidence": "797-808, 738-741", "reachability": "Assembled literal"},
            {"actor": "`_adm`", "authority": "`approval` mints", "evidence": "747-751", "reachability": "Role chain"},
            {"actor": "Current owner", "authority": "Owner branch, but A remains; can blacklist/rules", "evidence": "116-127", "reachability": "Not required for A"},
        ],
        "primitives": [
            {"name": "Hard-coded owner", "location": "116-127", "effect": "A or current owner, excluding C", "why": "A's authority is not revoked"},
            {"name": "Role chain", "location": "79, 146, 103, 140", "effect": "B → `_mbr` → `_user` → `_mod` → `_adm`", "why": "Second authority path"},
            {"name": "Mint paths", "location": "`_proof` 556-562; `approval` 747-751; `proof` 768-771; `_compute` 653-659; `decimal` 810-813", "effect": "Supply + balance increase", "why": "Dilution"},
            {"name": "Double credit", "location": "`_transferTo` 511-518; `_balanceView` 616-623", "effect": "+2a, supply +0", "why": "Ledger inflation"},
            {"name": "P-controlled rules", "location": "`reviewRules` 790-795", "effect": "Changes pair, trade-limited flag, min/max", "why": "Can freeze or reshape trading without owner"},
            {"name": "Blacklist + holding limits", "location": "`_beforeTokenTransfer` 773-788", "effect": "Blocks from/to blacklist; limits buys from pair", "why": "Exit/entry controls"},
            {"name": "Initial pair gate", "location": "780-783", "effect": "If pair is zero, only owner transfers", "why": "Trading can be dormant until operator opens it"},
        ],
        "paths": [
            {"function": "`proof(amount)`", "gate": "A or owner", "effect": "Mint to caller", "evidence": "768-771"},
            {"function": "`approval(amount)`", "gate": "`_adm`", "effect": "Mint to `_adm`", "evidence": "747-751"},
            {"function": "`decimal(amount)`", "gate": "P", "effect": "Mint to P", "evidence": "810-813, 653-659"},
            {"function": "`transferTo(to, amount)`", "gate": "A or owner", "effect": "Double-credit `to`", "evidence": "815-817, 511-518"},
            {"function": "`viewBalance(to, amount)`", "gate": "P", "effect": "Double-credit `to`", "evidence": "757-759, 616-623"},
            {"function": "`reviewRules(...)`", "gate": "P", "effect": "Changes pair/limits/trade flag", "evidence": "790-795"},
            {"function": "`blacklist`", "gate": "A or owner", "effect": "Sets from/to blacklist flag", "evidence": "753-755"},
            {"function": "`setPrinciplesRules(...)`", "gate": "A or owner", "effect": "Changes pair/limits/trade flag", "evidence": "761-766"},
        ],
        "invariants": [
            "`renounceOwnership` clears the stored owner but not A's branch.",
            "P can change trading rules independently of owner.",
            "`totalSupply` is mutable through at least four paths.",
            "`transferTo`/`viewBalance` can break the supply/balance-sum invariant.",
            "If `LiquiduniswapV2Pair == address(0)`, only owner addresses can transfer.",
        ],
        "numbers": [
            "`proof(1e18)` adds 1e18 supply and balance.",
            "`viewBalance(buyer, 100)` adds 200 to buyer, 0 to supply.",
            "Holder with 100,000 of 1,000,000 is diluted from 10% to 5% by a 1,000,000 mint.",
            "Default holding limits are zero; if `tradelimited` is true and max is zero, buys from the pair fail.",
        ],
        "signals": [
            "A file named 'normal' with hard-coded decimal addresses and `publics()` assembly.",
            "OZ ERC20 plus non-standard `proof`, `approval`, `decimal`, `transferTo`, `viewBalance`.",
            "`reviewRules` gated by a fragment-assembled address, not owner.",
            "`_beforeTokenTransfer` owner-only branch when pair is zero.",
            "Double `+=` in `_transferTo`/`_balanceView`.",
            "`onlyOwner` is `(literal || owner() == sender && sender != C)`.",
        ],
        "tests": [
            "Deploy with no pair: attempt a non-owner transfer; expect revert.",
            "Set pair as owner, buy, then call `reviewRules(tradelimited=true, pair, max=0, min=0)` from P; attempt a buy.",
            "Mint via `proof` and `decimal`; compare supply and holder shares.",
            "Renounce owner, then call `proof` from A.",
            "Blacklist a recipient and a sender separately; confirm both directions are blocked.",
        ],
        "limits": [COMMON_LIMIT, "No live pair or token deployment was inspected; 'buy from pair' refers to the source-level `_beforeTokenTransfer` condition, not measured router behavior."],
        "errata": [
            "Prior docs label Session 10 'normal/non-honeypot' or merely 'should be audited'; source contains hidden mint, double-credit, role-chain, and P-rule controls.",
            "The name `_beforeTokenTransfer` is OZ-shaped but the overridden rules are not standard OZ.",
            "`renounceOwnership` is not a safety feature here.",
        ],
        "related": ["13", "14", "12"],
    },
    {
        "id": "11",
        "slug": "session-11-ownership-renounce-meme-token",
        "dir": "token",
        "file": "session-11-ownership-renounce-meme-token.sol",
        "title": "Ownership-renounce meme token — conventional fixed-supply BEP-20",
        "classification": "No hidden control found (clean in scope)",
        "verdict": "clean",
        "confidence": "High for the listed surface; no compiler/fork run",
        "pragma": "0.5.16",
        "lines": 588,
        "sha256": "89c0524413007c54e2f6914b01162ba976003480f787867094f1f88d88123fa9",
        "summary": (
            "A conventional fixed-supply BEP-20 with standard transfer, approval, and "
            "allowance behavior. `renounceOwnership` revokes the only owner role, and no "
            "external function calls the internal `_mint`. The internal `_burn` and "
            "`_mint` exist but are not reachable from the public surface."
        ),
        "user_experience": (
            "Transfers and approvals behave normally. The deployer owns the initial "
            "supply and can renounce ownership; after that there is no privileged mint, "
            "fee, blacklist, or transfer gate. There is no upgrade proxy."
        ),
        "control": [
            {"actor": "Deployer", "authority": "Initial `_owner`; can renounce or transfer ownership", "evidence": "Ownable 280-337; constructor 351-359", "reachability": "Only until renounce"},
            {"actor": "Anyone", "authority": "Standard transfer/approve/transferFrom", "evidence": "411-518", "reachability": "No allowlist"},
        ],
        "primitives": [
            {"name": "Fixed supply", "location": "constructor 351-359", "effect": "1,000,000 * 10^18 assigned once", "why": "No public mint"},
            {"name": "Internal-only mint", "location": "`_mint` 530-536", "effect": "No external caller", "why": "Not an inflation path in this file"},
            {"name": "Standard allowance", "location": "447-451", "effect": "Subtracts allowance after transfer", "why": "No hidden exit gate"},
            {"name": "Renounce", "location": "316-321", "effect": "Sets `_owner = 0`; no hard-coded fallback", "why": "Actually removes owner powers"},
        ],
        "paths": [
            {"function": "`transfer` / `transferFrom`", "gate": "balance + allowance", "effect": "Standard movement", "evidence": "411-451"},
            {"function": "`approve` / increase / decrease", "gate": "caller", "effect": "Standard allowance", "evidence": "430-486"},
            {"function": "`renounceOwnership`", "gate": "owner", "effect": "Revokes owner", "evidence": "316-321"},
        ],
        "invariants": [
            "`_totalSupply` is assigned only in the constructor; no external `_mint` call exists.",
            "No address literal or fragment assembly is present.",
            "No blacklist, fee, or transfer gate is present.",
            "After renounce, no function checks the old owner.",
        ],
        "numbers": [
            "Supply = 1,000,000 * 10^18 = 1,000,000,000,000,000,000,000,000 base units.",
            "No fee example applies; transfers move the exact amount.",
        ],
        "signals": [
            "No `address(<decimal>)` or shifted-fragment address.",
            "No `onlyOwner` on a value-moving function other than renounce/transferOwnership.",
            "`_mint` has no call site.",
            "No UUPS import or initializer.",
        ],
        "tests": [
            "Call `renounceOwnership`; then call every external function and confirm none is owner-gated.",
            "Search the AST/call graph for `_mint` callers; expect none.",
            "Fuzz transfer/approve/transferFrom against a reference ERC-20.",
        ],
        "limits": [COMMON_LIMIT, "Standard ERC-20 approval-race and fee-on-transfer absence are noted, not treated as honeypot findings."],
        "errata": [
            "Prior docs suggest renounce might be bypassable; source has no hard-coded fallback and no other owner-gated value path.",
            "The internal `_mint` is not an external mint; it has no call site in this file.",
        ],
        "related": ["12", "15"],
    },
    {
        "id": "12",
        "slug": "session-12-auto-ownership-renounce-meme-token",
        "dir": "token",
        "file": "session-12-auto-ownership-renounce-meme-token.sol",
        "title": "Auto-renounce meme token — fixed supply, owner revoked in constructor",
        "classification": "No hidden control found (clean in scope)",
        "verdict": "clean",
        "confidence": "High for the listed surface; no compiler/fork run",
        "pragma": "^0.8.0",
        "lines": 90,
        "sha256": "c5e24018b2e582faba386255c63c04000686fd90fb71a528a5e922a0e0d58a7e",
        "summary": (
            "A small fixed-supply token. The constructor assigns the entire supply, sets "
            "`owner`, emits events, then calls `renounceOwnership()`. After deployment the "
            "owner is zero and no privileged function remains. Transfers use checked "
            "0.8 arithmetic around an `unchecked` block that is guarded by a prior balance "
            "check."
        ),
        "user_experience": (
            "The deployer starts with all tokens, then immediately renounces. There is no "
            "mint, fee, blacklist, pause, proxy, or owner-only value path. Trading is "
            "ordinary ERC-20 transfer/approve/transferFrom."
        ),
        "control": [
            {"actor": "Deployer", "authority": "Initial supply; owner is renounced in the constructor", "evidence": "constructor 24-30", "reachability": "No residual privilege"},
            {"actor": "Anyone", "authority": "Standard transfer/approve/transferFrom", "evidence": "36-84", "reachability": "No allowlist"},
        ],
        "primitives": [
            {"name": "Auto-renounce", "location": "constructor 24-30", "effect": "Sets owner to zero before deployment completes", "why": "No lingering owner"},
            {"name": "Fixed supply", "location": "line 8", "effect": "1e24 base units", "why": "No mint function"},
            {"name": "Guarded unchecked transfer", "location": "41-54", "effect": "Requires sender balance before unchecked subtraction", "why": "No underflow in this path"},
            {"name": "No hooks/proxy", "location": "whole file", "effect": "No hidden callback or upgrade", "why": "Small attack surface"},
        ],
        "paths": [
            {"function": "`transfer` / `transferFrom`", "gate": "balance + allowance", "effect": "Standard movement", "evidence": "36-84"},
            {"function": "`approve`", "gate": "caller", "effect": "Standard allowance", "evidence": "56-67"},
            {"function": "`renounceOwnership`", "gate": "owner, but owner is already zero", "effect": "No further privilege", "evidence": "86-89"},
        ],
        "invariants": [
            "`owner == address(0)` after construction.",
            "`totalSupply` is a state variable set once and never modified.",
            "No external function changes `_balances` except transfer/transferFrom.",
        ],
        "numbers": [
            "Supply = 1,000,000 * 10^18 = 1e24 base units.",
            "Transfer of 1000 moves exactly 1000; no fee.",
        ],
        "signals": [
            "No address literal, no role chain, no mint/fee/blacklist.",
            "Constructor calls `renounceOwnership`.",
            "Only owner-gated function is renounce itself.",
        ],
        "tests": [
            "Read `owner()` after deployment; expect zero.",
            "Attempt to call every function as a non-owner; expect normal ERC-20 results.",
            "Fuzz transferFrom allowance edge cases.",
        ],
        "limits": [COMMON_LIMIT, "This is a source-scope clean verdict; it is not an economic or deployment audit."],
        "errata": [
            "Prior docs say the renounce claim 'requires verification'; the constructor and owner state verify it directly.",
            "The `unchecked` block is guarded by a prior `require`; do not report it as a standalone underflow bug.",
        ],
        "related": ["11", "15"],
    },
    {
        "id": "13",
        "slug": "session-13-unlimited-supply-meme-token",
        "dir": "token",
        "file": "session-13-unlimited-supply-meme-token.sol",
        "title": "Unlimited-supply meme token — Session 10 plus owner `print` mint",
        "classification": "Malicious hidden control",
        "verdict": "malicious",
        "confidence": "High for source-level control; deployment not tested",
        "pragma": "^0.8.0",
        "lines": 827,
        "sha256": "57caed22640a34bc752bbb0397d106ae572f0bd82005682a41961fd52b5a0122",
        "summary": (
            "Session 10 with an additional owner-only `print` function that calls "
            "`_printbrr`. The rest of the hidden control plane is unchanged: A-or-owner "
            "gate, B-started role chain, P-controlled rules and `decimal`, `_adm` "
            "`approval`, and double-credit transfer helpers. The filename's 'unlimited "
            "supply' is accurate."
        ),
        "user_experience": (
            "The token can be paused for non-owners by leaving the pair unset, can be "
            "blacklisted, and can be diluted or double-credited by privileged actors. "
            "The owner can print new supply directly, in addition to the other mint "
            "routes."
        ),
        "control": [
            {"actor": "A = " + A, "authority": "Hard-coded owner; `proof`, `print`, blacklist, rules, transferTo", "evidence": "116-127; `print` 823-826", "reachability": "Direct"},
            {"actor": "B = " + B, "authority": "Starts role chain", "evidence": "79-93, 146, 103, 140", "reachability": "Direct"},
            {"actor": "P = " + P, "authority": "`naming`: viewBalance, decimal, reviewRules", "evidence": "797-808, 738-741", "reachability": "Assembled literal"},
            {"actor": "`_adm`", "authority": "`approval` mint", "evidence": "747-751", "reachability": "Role chain"},
        ],
        "primitives": [
            {"name": "Owner print", "location": "823-826", "effect": "`_printbrr` mints supply + balance", "why": "Direct inflation"},
            {"name": "All Session 10 controls", "location": "116-127, 79-751, 773-817", "effect": "Hard-coded owner, role chain, blacklist, pair gate, double credit", "why": "Inherited trap"},
            {"name": "P rules", "location": "790-795", "effect": "P changes pair/limits", "why": "Second operator can freeze trading"},
            {"name": "Double credit", "location": "511-518, 616-623", "effect": "+2a, supply +0", "why": "Ledger divergence"},
        ],
        "paths": [
            {"function": "`print(amount)`", "gate": "A or owner", "effect": "Mint to caller", "evidence": "823-826, 594-600"},
            {"function": "`proof` / `approval` / `decimal`", "gate": "A-or-owner / `_adm` / P", "effect": "Mint", "evidence": "768-771, 747-751, 810-813"},
            {"function": "`transferTo` / `viewBalance`", "gate": "A-or-owner / P", "effect": "Double credit", "evidence": "815-817, 757-759"},
            {"function": "`reviewRules`", "gate": "P", "effect": "Change pair/limits", "evidence": "790-795"},
            {"function": "`_beforeTokenTransfer`", "gate": "blacklist / pair / limits", "effect": "Transfer gate", "evidence": "773-788"},
        ],
        "invariants": [
            "Supply is unbounded through `print`, `proof`, `approval`, and `decimal`.",
            "A remains owner after renounce.",
            "P can change trading rules without owner.",
            "`transferTo`/`viewBalance` break the balance-sum invariant.",
        ],
        "numbers": [
            "`print(1e18)` adds 1e18 supply and balance.",
            "Holder 100k/1m diluted to 5% by +1m print.",
            "Double credit +2a; supply +0.",
        ],
        "signals": [
            "`print` calls `_printbrr`; `_printbrr` duplicates `_proof` mint logic.",
            "All Session 10 hidden-control signatures.",
            "P-only `reviewRules` and `decimal`.",
        ],
        "tests": [
            "Call `print` from A and compare supply/balance.",
            "Renounce, then call `print` from A.",
            "Attempt non-owner transfer with pair unset.",
            "Use P to set max holding to zero and buy.",
        ],
        "limits": [COMMON_LIMIT, "No deployment was inspected for actual pair configuration."],
        "errata": [
            "Prior docs classify this as 'unlimited supply' but do not connect `print` to the full Session 10 control plane.",
            "The `print` function is owner-gated, not public.",
        ],
        "related": ["10", "14"],
    },
    {
        "id": "14",
        "slug": "session-14-v2-unlimited-supply-meme-token",
        "dir": "token",
        "file": "session-14-v2-unlimited-supply-meme-token.sol",
        "title": "V2 unlimited-supply meme token — UUPS, public initialize, double supply",
        "classification": "Malicious hidden control (upgradeable, defective initialization)",
        "verdict": "broken",
        "confidence": "High for source-level behavior; proxy not executed",
        "pragma": "^0.8.0",
        "lines": 833,
        "sha256": "f1618a898d4d5605846f52d69ca833293a3a9f78b731cc09d8615f1bbd899267",
        "summary": (
            "A UUPS port of Session 13. It retains the hard-coded A owner, role chain, "
            "blacklist, P rules, `proof`/`print`/`approval`/`decimal` mints, and double-"
            "credit helpers. It adds a public `initialize` with no `_disableInitializers` "
            "and sets `totalSupply` before calling `_mint`, which adds the supply a second "
            "time. The result is totalSupply = 2T with balance T on first initialization."
        ),
        "user_experience": (
            "The first initializer can take ownership and supply if deployment is not "
            "atomic. The initialized ledger immediately reports twice the minted supply. "
            "After that, the same privileged mint/double-credit/rule controls as Session "
            "13 remain, and A survives renounce."
        ),
        "control": [
            {"actor": "First initializer", "authority": "Becomes `owner`; receives `_totalSupply` balance", "evidence": "641-652", "reachability": "Public, one-shot custom bool; no disable"},
            {"actor": "A = " + A, "authority": "Hard-coded owner; `proof`, `print`, blacklist, rules, transferTo, upgrade", "evidence": "703-714; upgrade 737", "reachability": "Direct"},
            {"actor": "B = " + B, "authority": "Starts role chain", "evidence": "659-673, 743, 690, 727", "reachability": "Direct"},
            {"actor": "P = " + P, "authority": "`naming`: viewBalance, decimal, reviewRules", "evidence": "807-818, 634-637", "reachability": "Assembled literal"},
            {"actor": "`_adm`", "authority": "`approval` mint", "evidence": "768-772", "reachability": "Role chain"},
        ],
        "primitives": [
            {"name": "Public initialize", "location": "641-652", "effect": "No `_disableInitializers`; first caller owns and mints", "why": "Deployment race"},
            {"name": "Double supply on initialize", "location": "646, 649, 457-467", "effect": "`totalSupply = T` then `_mint` adds T → 2T", "why": "Broken invariant from block one"},
            {"name": "UUPS upgrade", "location": "737", "effect": "A or owner can replace implementation", "why": "A can change code"},
            {"name": "Owner print", "location": "829-832", "effect": "Mint", "why": "Unbounded supply"},
            {"name": "Role/blacklist/rules", "location": "659-790", "effect": "Session 13 control plane", "why": "Multiple hidden authorities"},
            {"name": "Double credit", "location": "395-402, 500-507", "effect": "+2a, supply +0", "why": "Ledger inflation"},
        ],
        "paths": [
            {"function": "`initialize`", "gate": "public, `!initialized`", "effect": "Double-counts supply; sets owner", "evidence": "641-652, 457-467"},
            {"function": "`print` / `proof`", "gate": "A or owner", "effect": "Mint", "evidence": "829-832, 785-788"},
            {"function": "`approval` / `decimal`", "gate": "`_adm` / P", "effect": "Mint", "evidence": "768-772, 820-823"},
            {"function": "`transferTo` / `viewBalance`", "gate": "A-or-owner / P", "effect": "Double credit", "evidence": "733-735, 696-698"},
            {"function": "`_authorizeUpgrade`", "gate": "A or owner", "effect": "Upgrade implementation", "evidence": "737"},
        ],
        "invariants": [
            "After initialize(T), `totalSupply == 2T` and `balanceOf(initializer) == T`.",
            "`initialized` is true after the first initialize, but the implementation has no disabled initializer state.",
            "A remains owner after renounce.",
            "Supply is unbounded via print/proof/approval/decimal.",
            "`owner` is private, but onlyOwner still includes A.",
        ],
        "numbers": [
            "T=1e24: initialize -> totalSupply=2e24, initializer balance=1e24.",
            "`print(1e18)` -> supply +1e18, balance +1e18.",
            "Double credit +2a; supply +0.",
        ],
        "signals": [
            "UUPS import + public initialize + no `_disableInitializers`.",
            "`initialize` assigns `totalSupply = _totalSupply` and then calls `_mint`.",
            "Hard-coded A in `onlyOwner` and `_authorizeUpgrade`.",
            "P-only `reviewRules`/`decimal`, `_adm` `approval`, owner `print`/`proof`.",
            "Double `+=` helpers.",
        ],
        "tests": [
            "Initialize a fresh proxy with T; read totalSupply and balance; expect 2T/ T.",
            "Attempt a second initialize; expect revert on the custom bool.",
            "Deploy implementation and initialize it directly from a non-deployer.",
            "Renounce, then print from A; then upgrade from A.",
        ],
        "limits": [COMMON_LIMIT, "The double-supply result is a source-level arithmetic conclusion; proxy storage/delegatecall was not executed."],
        "errata": [
            "Prior docs call this 'V2 unlimited supply' but miss that initialization itself doubles the reported supply.",
            "Prior docs do not mention public initialize, no initializer disable, or A's upgrade authority.",
            "The double credit is in the helpers, not the no-op tuple expression.",
        ],
        "related": ["13", "10", "08"],
    },
    {
        "id": "15",
        "slug": "session-15-v2-auto-ownership-renounce-meme-token",
        "dir": "token",
        "file": "session-15-v2-auto-ownership-renounce-meme-token.sol",
        "title": "V2 auto-renounce meme token — constants, fixed supply, no proxy",
        "classification": "No hidden control found (clean in scope)",
        "verdict": "clean",
        "confidence": "High for the listed surface; no compiler/fork run",
        "pragma": "^0.8.0",
        "lines": 90,
        "sha256": "51cd7d72381d026b515e6365b22d791f659b8afe8badb7600cac95ba8e029538",
        "summary": (
            "A constant-state variant of Session 12. `name`, `symbol`, `decimals`, and "
            "`totalSupply` are constants; the constructor assigns the supply and "
            "immediately renounces ownership. There is no mint, fee, blacklist, proxy, or "
            "owner-only value path. The 'V2' label does not imply upgradeability."
        ),
        "user_experience": (
            "The deployer starts with all tokens and ownership is immediately burned. "
            "Transfers and approvals are standard. No operator can mint, freeze, tax, or "
            "upgrade the token through this source surface."
        ),
        "control": [
            {"actor": "Deployer", "authority": "Initial supply; auto-renounces in constructor", "evidence": "24-30", "reachability": "No residual privilege"},
            {"actor": "Anyone", "authority": "Standard transfer/approve/transferFrom", "evidence": "36-84", "reachability": "No allowlist"},
        ],
        "primitives": [
            {"name": "Constants", "location": "5-8", "effect": "Compile-time metadata and supply", "why": "Cannot be changed at runtime"},
            {"name": "Auto-renounce", "location": "24-30", "effect": "Owner zero after deployment", "why": "No lingering owner"},
            {"name": "Fixed supply", "location": "8, 25", "effect": "1e24 assigned once", "why": "No mint path"},
            {"name": "No proxy", "location": "whole file", "effect": "No UUPS/initializer", "why": "No upgrade authority"},
        ],
        "paths": [
            {"function": "`transfer` / `transferFrom`", "gate": "balance + allowance", "effect": "Standard movement", "evidence": "36-84"},
            {"function": "`approve`", "gate": "caller", "effect": "Standard allowance", "evidence": "56-67"},
            {"function": "`renounceOwnership`", "gate": "owner, already zero", "effect": "No further privilege", "evidence": "86-89"},
        ],
        "invariants": [
            "`owner == address(0)` after construction.",
            "`totalSupply` is constant and never changes.",
            "No external function mint/burn/blacklist/fee.",
        ],
        "numbers": [
            "Supply = 1e24 base units.",
            "Transfer of 1000 moves exactly 1000; no fee.",
        ],
        "signals": [
            "No address literal/fragment assembly, no UUPS import, no initializer.",
            "Constructor calls renounceOwnership.",
            "Only owner-gated function is renounce.",
        ],
        "tests": [
            "Read owner after deployment; expect zero.",
            "Call renounce again; expect revert because owner is zero.",
            "Fuzz standard transfer/allowance behavior.",
        ],
        "limits": [COMMON_LIMIT, "Source-scope clean verdict only; no economic or deployment audit."],
        "errata": [
            "Prior docs call this 'V2' and imply a possible upgrade path; source has no proxy or initializer.",
            "Prior docs say the renounce claim needs verification; construction directly sets then clears owner.",
        ],
        "related": ["12", "11"],
    },
]


def by_id() -> dict[str, dict]:
    return {s["id"]: s for s in SESSIONS}
