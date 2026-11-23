#!/usr/bin/env python3
"""Static indicator scanner for defensive Solidity token review.

This is a *triage* tool. A hit is a reason to read the code, not a verdict.
It uses only the Python standard library.

Usage:
    python -I scan_indicators.py <file.sol | directory> [...] [--json]

The scanner strips comments before matching, so address literals split across
lines by comments are still found. It also reports the source line and the
matched expression as evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Source masking and brace matching
# ---------------------------------------------------------------------------


def mask_comments(src: str) -> str:
    """Replace comments with spaces/newlines, preserving length and lines.

    String literals are copied verbatim (with escapes handled) so that braces
    and slashes inside strings do not confuse the block finder.
    """
    out: list[str] = []
    i = 0
    n = len(src)
    state = "code"
    while i < n:
        if state == "code":
            if src.startswith("//", i):
                out.append("  ")
                i += 2
                state = "line"
                continue
            if src.startswith("/*", i):
                out.append("  ")
                i += 2
                state = "block"
                continue
            ch = src[i]
            if ch in ("'", '"'):
                quote = ch
                out.append(ch)
                i += 1
                while i < n:
                    out.append(src[i])
                    if src[i] == "\\" and i + 1 < n:
                        out.append(src[i + 1])
                        i += 2
                        continue
                    if src[i] == quote:
                        i += 1
                        break
                    i += 1
                continue
            out.append(ch)
            i += 1
        elif state == "line":
            if src[i] == "\n":
                out.append("\n")
                state = "code"
            else:
                out.append(" ")
            i += 1
        else:  # block comment
            if src.startswith("*/", i):
                out.append("  ")
                i += 2
                state = "code"
            elif src[i] == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" ")
                i += 1
    return "".join(out)


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _skip_string(text: str, i: int) -> int:
    quote = text[i]
    i += 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
        elif text[i] == quote:
            return i + 1
        else:
            i += 1
    return i


def matching_brace(text: str, open_pos: int) -> int:
    """Return index just past the matching '}' for the '{' at open_pos."""
    depth = 0
    i = open_pos
    while i < len(text):
        ch = text[i]
        if ch in ("'", '"'):
            i = _skip_string(text, i)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


BLOCK_RE = re.compile(
    r"\b(?P<kind>function|modifier|constructor|fallback|receive)\s+"
    r"(?P<name>[A-Za-z_]\w*)?\s*\([^;{}]*\)\s*[^{;]*\{",
    re.S,
)


def blocks(src: str) -> list[dict]:
    """Return function/modifier blocks with name, line, signature and body."""
    found: list[dict] = []
    for m in BLOCK_RE.finditer(src):
        open_pos = m.end() - 1
        end = matching_brace(src, open_pos)
        kind = m.group("kind")
        name = m.group("name") or kind
        found.append(
            {
                "kind": kind,
                "name": name,
                "line": line_of(src, m.start()),
                "signature": re.sub(r"\s+", " ", src[m.start() : open_pos]).strip(),
                "body": src[open_pos + 1 : end - 1],
            }
        )
    return found


def enclosing_block(bl: list[dict], line: int) -> str:
    candidates = [b for b in bl if b["line"] <= line]
    return candidates[-1]["name"] if candidates else ""


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------

DEC_ADDR_RE = re.compile(r"address\s*\(\s*(\d{20,})\s*\)")
HEX_ADDR_RE = re.compile(r"address\s*\(\s*(0x[0-9a-fA-F]{40})\s*\)")
ANY_HEX40_RE = re.compile(r"0x[0-9a-fA-F]{40}")
FRAGMENT_RE = re.compile(r"uint160\s*\([^;]*?\)\s*<<\s*(?:128|96|64|32)")
NEG_GUARD_RE = re.compile(r"msg\.sender\s*!=\s*([A-Za-z_]\w*)\s*\(")
ASSIGN_RE = re.compile(
    r"(?P<lhs>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?(?:\s*\[[^\]]+\])?)\s*=\s*(?!=)(?P<rhs>[^;]+);"
)
PLUS_EQ_RE = re.compile(r"(?P<lhs>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?(?:\s*\[[^\]]+\])?)\s*\+=\s*(?P<rhs>[^;]+);")
REQUIRE_RE = re.compile(r"require\s*\((?P<expr>.*?)\)\s*;", re.S)
FEE_CAP_RE = re.compile(r"[^;\n]*<=\s*100[^;\n]*;")
ROLE_NAMES = ("setMember", "setUser", "setMod", "setAdm", "setUsdtPair", "setMedium")
MINT_CALLS = ("_mint", "_proof", "_compute", "_printbrr", "_initiate", "_scale", "_calculate", "_dialone")
CREDIT_CALLS = ("_transferTo", "_balanceView")
ROLE_ASSIGN_RE = re.compile(r"(?P<var>_[A-Za-z]\w*)\s*=\s*[A-Za-z_]\w*\s*;")
STORED_OWNER_RE = re.compile(r"(?:\b_owner\b|\bowner\b)\s*(?:\(\))?\s*==|==\s*(?:\b_owner\b|\bowner\b)")


def hex_addr(n: int) -> str:
    return "0x%040x" % n


def role_info(bl: list[dict]) -> dict:
    """Describe role-setter chain edges.

    Edges are only emitted when the guard is a direct comparison and the
    source is either a public role variable or a hard-coded literal. This is
    deliberately conservative: a missed edge is better than an invented one.
    """
    setters: list[dict] = []
    edges: list[dict] = []
    writes: dict[str, str] = {}
    for b in bl:
        if b["name"] not in ROLE_NAMES:
            continue
        req = REQUIRE_RE.search(b["body"])
        guard = re.sub(r"\s+", " ", req.group("expr")).strip() if req else ""
        m = ROLE_ASSIGN_RE.search(b["body"])
        target = m.group("var") if m else ""
        source: str | None = None
        source_kind = "none"
        vm = re.search(r"(?:msg\.sender|_msgSender\(\))\s*==\s*([A-Za-z_]\w*)", guard)
        if vm and vm.group(1) != "address":
            source, source_kind = vm.group(1), "role"
        else:
            dm = DEC_ADDR_RE.search(guard)
            if dm:
                source, source_kind = dm.group(1), "decimal_literal"
            else:
                hm = HEX_ADDR_RE.search(guard)
                if hm:
                    source, source_kind = hm.group(1), "hex_literal"
        setters.append(
            {
                "name": b["name"],
                "line": b["line"],
                "guard": guard,
                "source": source,
                "source_kind": source_kind,
                "writes": target,
            }
        )
        if target:
            writes[target] = b["name"]
    for s in setters:
        if s["writes"] and s["source"]:
            # Keep a literal's canonical hex form in the report.
            if s["source_kind"] == "decimal_literal":
                src = hex_addr(int(s["source"]))
            elif s["source_kind"] == "hex_literal":
                src = s["source"]
            else:
                src = s["source"]
            if s["source_kind"] != "role" or src in writes:
                edges.append(
                    {
                        "from": src,
                        "from_kind": s["source_kind"],
                        "to": s["writes"],
                        "setter": s["name"],
                    }
                )
    return {"setters": setters, "edges": edges}


def owner_gate_info(bl: list[dict]) -> dict:
    """Summarise onlyOwner gates and whether renounceOwnership is effective."""
    gates: list[dict] = []
    hardcoded_owners: list[str] = []
    for b in bl:
        if b["kind"] != "modifier" or b["name"] != "onlyOwner":
            continue
        body = b["body"]
        literals = []
        for m in DEC_ADDR_RE.finditer(body):
            n = int(m.group(1))
            if n < 2**160:
                literals.append(hex_addr(n))
        literals.extend(m.group(1) for m in HEX_ADDR_RE.finditer(body))
        hardcoded_owners.extend(literals)
        gates.append(
            {
                "line": b["line"],
                "hardcoded": literals,
                "stored_owner": bool(STORED_OWNER_RE.search(body)),
                "excludes_exchange": "exchange()" in body,
                "expression": re.sub(r"\s+", " ", body).strip(),
            }
        )
    renounce = next((b for b in bl if b["name"] == "renounceOwnership"), None)
    effective = "not_present"
    if renounce:
        if not gates:
            effective = "unknown_no_onlyowner_gate"
        elif any(g["hardcoded"] for g in gates):
            effective = "does_not_revoke_hardcoded_owner"
        elif any(g["stored_owner"] for g in gates):
            effective = "revokes_stored_owner_only"
        else:
            effective = "unknown"
    return {
        "gates": gates,
        "hardcoded_owners": sorted(set(hardcoded_owners)),
        "renounce_effective": effective,
    }


def scan_file(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8", errors="replace")
    src = mask_comments(raw)
    bl = blocks(src)

    decimal: list[dict] = []
    for m in DEC_ADDR_RE.finditer(src):
        n = int(m.group(1))
        decimal.append(
            {
                "line": line_of(src, m.start()),
                "literal": m.group(1),
                "hex": hex_addr(n) if n < 2**160 else None,
                "in_function_or_modifier": enclosing_block(bl, line_of(src, m.start())),
            }
        )

    hex_literals: list[dict] = []
    for m in HEX_ADDR_RE.finditer(src):
        hex_literals.append(
            {
                "line": line_of(src, m.start()),
                "literal": m.group(1),
                "in_function_or_modifier": enclosing_block(bl, line_of(src, m.start())),
            }
        )

    fragments: list[dict] = []
    for b in bl:
        if FRAGMENT_RE.search(b["body"]):
            consts = re.findall(r"0x[0-9a-fA-F]{1,8}", b["body"])
            computed = None
            if len(consts) >= 5:
                vals = [int(x, 16) for x in consts[:5]]
                computed = hex_addr((vals[0] << 128) | (vals[1] << 96) | (vals[2] << 64) | (vals[3] << 32) | vals[4])
            fragments.append(
                {
                    "line": b["line"],
                    "function": b["name"],
                    "constants": consts,
                    "computed_address": computed,
                }
            )

    mod_hard: list[dict] = []
    for b in bl:
        if b["kind"] != "modifier":
            continue
        literals = [x["literal"] for x in decimal if b["line"] <= x["line"] <= b["line"] + b["body"].count("\n") + 1]
        literals += [x["literal"] for x in hex_literals if b["line"] <= x["line"] <= b["line"] + b["body"].count("\n") + 1]
        if literals:
            mod_hard.append({"modifier": b["name"], "line": b["line"], "literals": literals})

    neg_guards: list[dict] = []
    for m in NEG_GUARD_RE.finditer(src):
        ln = line_of(src, m.start())
        neg_guards.append(
            {"line": ln, "guard": re.sub(r"\s+", " ", m.group(0)).strip(), "in": enclosing_block(bl, ln)}
        )

    balance_assignments: list[dict] = []
    for m in ASSIGN_RE.finditer(src):
        lhs = re.sub(r"\s+", " ", m.group("lhs")).strip()
        # Only mapping/storage writes are balance mutations. A local variable
        # such as `uint256 senderBalance = ...` is not a ledger write.
        if not re.search(r"(?i)balance", lhs) or "[" not in lhs:
            continue
        rhs = re.sub(r"\s+", " ", m.group("rhs")).strip()
        arithmetic = bool(re.search(r"[+\-]|\.add\s*\(|\.sub\s*\(", rhs))
        balance_assignments.append(
            {
                "line": line_of(src, m.start()),
                "lhs": lhs,
                "rhs": rhs,
                "add_or_subtract": arithmetic,
                "in": enclosing_block(bl, line_of(src, m.start())),
            }
        )

    double_credit: list[dict] = []
    for b in bl:
        groups: dict[str, list[str]] = {}
        for m in PLUS_EQ_RE.finditer(b["body"]):
            lhs = re.sub(r"\s+", " ", m.group("lhs")).strip()
            if not re.search(r"(?i)balance", lhs):
                continue
            groups.setdefault(lhs, []).append(re.sub(r"\s+", " ", m.group("rhs")).strip())
        for lhs, rhs in groups.items():
            if len(rhs) < 2:
                continue
            if re.search(re.escape(lhs) + r"\s*-=", b["body"]):
                continue
            if re.search(r"totalSupply\s*(=|\+=|-=)", b["body"]):
                continue
            double_credit.append(
                {
                    "line": b["line"],
                    "function": b["name"],
                    "lhs": lhs,
                    "credits": len(rhs),
                    "rhs": rhs,
                }
            )

    fee_caps = []
    for m in FEE_CAP_RE.finditer(src):
        stmt = re.sub(r"\s+", " ", m.group(0)).strip()
        fee_caps.append({"line": line_of(src, m.start()), "statement": stmt})

    gate_info = owner_gate_info(bl)
    renounce = {
        "present": False,
        "line": None,
        "guard": None,
        "hardcoded_owner_fallback": bool(gate_info["hardcoded_owners"]),
        "effective": gate_info["renounce_effective"],
        "called_from": [],
    }
    for b in bl:
        if b["name"] == "renounceOwnership":
            renounce["present"] = True
            renounce["line"] = b["line"]
            req = REQUIRE_RE.search(b["body"])
            renounce["guard"] = re.sub(r"\s+", " ", req.group("expr")).strip() if req else None
        if re.search(r"\brenounceOwnership\s*\(\s*\)", b["body"]) and b["name"] != "renounceOwnership":
            renounce["called_from"].append(b["name"])

    init_functions = []
    for b in bl:
        if b["name"] == "initialize":
            init_functions.append({"line": b["line"], "signature": b["signature"]})

    mint_like = []
    for b in bl:
        calls = [c for c in MINT_CALLS + CREDIT_CALLS if re.search(r"\b" + re.escape(c) + r"\s*\(", b["body"])]
        if calls:
            mint_like.append(
                {
                    "line": b["line"],
                    "function": b["name"],
                    "calls": calls,
                    "signature": b["signature"],
                }
            )

    transfer_paths = []
    for b in bl:
        if b["name"] in ("transfer", "transferFrom", "_transfer", "_beforeTokenTransfer", "ensure", "condition", "buy", "sell", "_computing", "approval", "approveAndCall"):
            reqs = [re.sub(r"\s+", " ", x.group("expr")).strip() for x in REQUIRE_RE.finditer(b["body"])]
            transfer_paths.append({"line": b["line"], "function": b["name"], "requires": reqs})

    pragma = None
    pm = re.search(r"pragma\s+solidity\s+([^;]+);", src)
    if pm:
        pragma = pm.group(1).strip()

    return {
        "file": path.as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "lines": raw.count("\n") + (0 if raw.endswith("\n") else 1),
        "pragma": pragma,
        "decimal_address_literals": decimal,
        "hex_address_literals": hex_literals,
        "fragment_assembled_addresses": fragments,
        "modifiers_with_hardcoded_address": mod_hard,
        "msg_sender_not_function_guards": neg_guards,
        "balance_assignments": balance_assignments,
        "double_credit_helpers": double_credit,
        "role_chain": role_info(bl),
        "owner_gate": gate_info,
        "fee_caps_100": fee_caps,
        "renounce_ownership": renounce,
        "uups": {
            "imports_uups": "UUPSUpgradeable" in src,
            "initialize_functions": init_functions,
            "authorize_upgrade": [b["name"] for b in bl if b["name"] == "_authorizeUpgrade"],
            "disable_initializers": "_disableInitializers" in src,
        },
        "mint_or_credit_functions": mint_like,
        "transfer_paths": transfer_paths,
    }


def summarize(row: dict) -> dict:
    return {
        "file": row["file"],
        "lines": row["lines"],
        "pragma": row["pragma"],
        "decimal_address_literals": len(row["decimal_address_literals"]),
        "fragment_assembled_addresses": len(row["fragment_assembled_addresses"]),
        "modifiers_with_hardcoded_address": [x["modifier"] for x in row["modifiers_with_hardcoded_address"]],
        "msg_sender_not_function_guards": [x["guard"] for x in row["msg_sender_not_function_guards"]],
        "balance_assignments_not_add_sub": sum(1 for x in row["balance_assignments"] if not x["add_or_subtract"]),
        "double_credit_helpers": [x["function"] for x in row["double_credit_helpers"]],
        "role_chain_edges": row["role_chain"]["edges"],
        "owner_gate": row["owner_gate"],
        "fee_caps_100": len(row["fee_caps_100"]),
        "renounce_ownership": row["renounce_ownership"],
        "uups": row["uups"],
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args(argv[1:])

    files: list[Path] = []
    for arg in args.paths:
        p = Path(arg)
        if p.is_dir():
            files.extend(sorted(p.rglob("*.sol")))
        else:
            files.append(p)

    rows = [scan_file(p) for p in files]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for r in rows:
        s = summarize(r)
        print(f"\n{r['file']}")
        for key, value in s.items():
            if key != "file":
                print(f"  {key}: {value}")
    if args.summary:
        print("\nSUMMARY")
        for r in rows:
            s = summarize(r)
            print(f"{s['file']}\t{s['pragma']}\tdec={s['decimal_address_literals']}\t"
                  f"frag={s['fragment_assembled_addresses']}\t"
                  f"mods={s['modifiers_with_hardcoded_address']}\t"
                  f"double={s['double_credit_helpers']}\tfee100={s['fee_caps_100']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
