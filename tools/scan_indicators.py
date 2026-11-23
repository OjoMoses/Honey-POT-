#!/usr/bin/env python3
"""Defensive static indicator scanner for Solidity honeypot triage.

Standard library only. Strips comments while preserving byte offsets/newlines,
then reports address literals (decimal, hex, fragment-assembled), privileged
modifiers, negative sender guards, balance writes and double credits, role
setter chains, fee ceilings, renounce and UUPS/initializer patterns.

This is a TRIAGE aid. A hit is evidence to read, never proof of behaviour;
the absence of hits is never proof of safety.

Usage:
    python3 tools/scan_indicators.py [path ...] [--json] [--out FILE]
"""
from __future__ import annotations

import ast
import json
import pathlib
import re
import sys
from collections import defaultdict

MASK160 = (1 << 160) - 1


def strip_comments_keep_offsets(src: str) -> str:
    """Replace comment bytes with spaces; keep newlines so line numbers survive."""
    out = list(src)
    i, n = 0, len(src)
    state = "code"
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == '"' or c == "'":
                state = "string"
            elif c == "/" and nxt == "/":
                state = "line"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            elif c == "/" and nxt == "*":
                state = "block"
                out[i] = out[i + 1] = " "
                i += 2
                continue
        elif state == "line":
            if c == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block":
            if c == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                state = "code"
                i += 2
                continue
            if c != "\n":
                out[i] = " "
        elif state == "string":
            if c == "\\":
                # keep the escape and its payload
                i += 2
                continue
            if c == '"' or c == "'":
                state = "code"
        i += 1
    return "".join(out)


def lines(src: str):
    return src.splitlines()


def lineno(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def dec_addr(n: int) -> str:
    return "0x%040x" % (n & MASK160)


DEC_IN_ADDR = re.compile(r"\baddress\s*\(\s*(\d{15,})\s*\)")
DEC_UINT160 = re.compile(r"\buint160\s*\(\s*(\d{15,})\s*\)")
BARE_DEC = re.compile(r"(?<![0-9A-Za-z_])(\d{38,})(?![0-9A-Za-z_])")
HEX_IN_ADDR = re.compile(r"\baddress\s*\(\s*(0x[0-9a-fA-F]{40})\s*\)")
BARE_HEX40 = re.compile(r"(?<![0-9A-Za-z_])(0x[0-9a-fA-F]{40})(?![0-9A-Za-z_])")
SHIFT_EXPR = re.compile(r"uint160\s*\([^;]*?<<\s*(?:128|96|64|32)[^;]*;", re.S)
MODIFIER = re.compile(r"\bmodifier\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*\{", re.S)
FUNCTION = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*([^{;]*)\{", re.S)
NEG_GUARD = re.compile(r"msg\.sender\s*!=\s*([A-Za-z_]\w*)\s*\(\s*\)")
BALANCE_SET = re.compile(
    r"\b((?:_?balances?|balanceOf|_?balance)\s*\[[^\]]+\])\s*(?:=|==)\s*([^;{}]+);"
)
PLUS_EQ = re.compile(r"\b([A-Za-z_]\w*(?:\[[^\]]+\])?)\s*\+=([^;]+);")
FEE_CAP = re.compile(
    r"\b([A-Za-z_]*[Ff]ee[A-Za-z_]*|[A-Za-z_]*[Tt]ax[A-Za-z_]*)\s*<=\s*(\d{1,3})\b"
)
ROLE_FN = re.compile(r"^set[A-Z]\w*$")


def balanced_body(src: str, open_brace: int) -> tuple[int, int]:
    depth, i, n = 0, open_brace, len(src)
    in_string = None
    while i < n:
        c = src[i]
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == in_string:
                in_string = None
        elif c in ('"', "'"):
            in_string = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return open_brace + 1, i
        i += 1
    return open_brace + 1, n


def blocks(src: str, pattern) -> list[dict]:
    out = []
    for m in pattern.finditer(src):
        ob = src.find("{", m.end() - 1)
        if ob < 0:
            continue
        start, end = balanced_body(src, ob)
        out.append({
            "name": m.group(1),
            "header": src[m.start():ob],
            "body": src[start:end],
            "body_start": start,
            "line": lineno(src, m.start()),
        })
    return out


ALLOWED_OPS = (ast.LShift, ast.RShift, ast.BitOr, ast.Add, ast.Mult)


def eval_fragment(expr: str, constants: dict[str, int] | None = None) -> str | None:
    """Safely evaluate uint160(...)/hex/shift/or expressions."""
    e = re.sub(r"\buint(?:160|256|128|64|32)\s*\(", "(", expr)
    e = re.sub(r"\baddress\s*\(", "(", e)
    if constants:
        # Longest names first so a short name cannot eat a prefix of a longer one.
        for name in sorted(constants, key=len, reverse=True):
            e = re.sub(r"\b%s\b" % re.escape(name), "(%d)" % constants[name], e)
    try:
        tree = ast.parse(e, mode="eval")
    except SyntaxError:
        return None

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -ev(node.operand)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ALLOWED_OPS):
            a, b = ev(node.left), ev(node.right)
            if a is None or b is None:
                return None
            if isinstance(node.op, ast.LShift):
                return a << b
            if isinstance(node.op, ast.RShift):
                return a >> b
            if isinstance(node.op, ast.BitOr):
                return a | b
            if isinstance(node.op, ast.Add):
                return a + b
            if isinstance(node.op, ast.Mult):
                return a * b
        return None

    val = ev(tree)
    return dec_addr(val) if val is not None and 0 <= val <= MASK160 else None


def find_fragments(src: str) -> list[dict]:
    found = []
    constants = {m.group(1): int(m.group(2), 16)
                 for m in re.finditer(r"\buint(?:256|160|128|64|32)?\s+([A-Za-z_]\w*)\s*=\s*(0x[0-9a-fA-F]+)\s*;", src)}
    statements = list(re.finditer(r"uint160\s+[A-Za-z_]\w*\s*=\s*([^;]+);", src))
    for m in SHIFT_EXPR.finditer(src):
        expr = m.group(0).rstrip(";")
        addr = eval_fragment(expr, constants)
        if addr is None:
            # Use the full assignment statement that contains this shift.
            for st in statements:
                if st.start() <= m.start() <= st.end():
                    addr = eval_fragment(st.group(1), constants)
                    expr = st.group(1)
                    break
        found.append({
            "line": lineno(src, m.start()),
            "expression": re.sub(r"\s+", " ", expr).strip(),
            "decoded_address": addr,
        })
    # de-duplicate identical expression/line pairs
    uniq, seen = [], set()
    for f in found:
        key = (f["line"], f["expression"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def find_decimals(src: str) -> list[dict]:
    out, seen = [], set()
    for rx in (DEC_IN_ADDR, DEC_UINT160, BARE_DEC):
        for m in rx.finditer(src):
            v = int(m.group(1))
            if v > MASK160:
                continue
            item = {"line": lineno(src, m.start()), "literal": m.group(1),
                    "decoded_address": dec_addr(v)}
            key = (item["line"], item["literal"])
            if key not in seen:
                seen.add(key)
                out.append(item)
    return sorted(out, key=lambda d: (d["line"], d["literal"]))


def find_hexes(src: str) -> list[dict]:
    out, seen = [], set()
    for rx in (HEX_IN_ADDR, BARE_HEX40):
        for m in rx.finditer(src):
            item = {"line": lineno(src, m.start()), "literal": m.group(1).lower()}
            key = (item["line"], item["literal"])
            if key not in seen:
                seen.add(key)
                out.append(item)
    return sorted(out, key=lambda d: (d["line"], d["literal"]))


def scan_text(raw: str, name: str) -> dict:
    src = strip_comments_keep_offsets(raw)
    decimals = find_decimals(src)
    hexes = find_hexes(src)
    fragments = find_fragments(src)
    addr_lines = {d["line"] for d in decimals} | {h["line"] for h in hexes} | {f["line"] for f in fragments}

    mods = []
    for b in blocks(src, MODIFIER):
        body_lines = set(range(b["line"], lineno(src, b["body_start"] + len(b["body"])) + 1))
        if body_lines & addr_lines or DEC_IN_ADDR.search(b["body"]) or HEX_IN_ADDR.search(b["body"]) or BARE_HEX40.search(b["body"]):
            mods.append({"name": b["name"], "line": b["line"],
                         "guard": re.sub(r"\s+", " ", b["body"]).strip()[:300]})

    neg = [{"line": lineno(src, m.start()), "function": m.group(1)}
           for m in NEG_GUARD.finditer(src)]

    bal_writes = []
    for m in BALANCE_SET.finditer(src):
        if m.group(0).startswith("==") or "==" in m.group(0)[:m.group(0).find(";")]:
            continue
        rhs = m.group(2).strip()
        if re.search(r"\+=|-=|\.add\(|\.sub\(|\+|\-", rhs):
            continue
        bal_writes.append({"line": lineno(src, m.start()), "lvalue": m.group(1).strip(),
                           "rhs": rhs[:160]})

    double = []
    for f in blocks(src, FUNCTION):
        counts = defaultdict(list)
        for m in PLUS_EQ.finditer(f["body"]):
            key = re.sub(r"\s+", "", m.group(1))
            amt = re.sub(r"\s+", "", m.group(2))
            counts[(key, amt)].append(lineno(src, f["body_start"] + m.start()))
        for (lval, amt), ls in counts.items():
            if len(ls) >= 2:
                double.append({"function": f["name"], "lvalue": lval, "amount": amt, "lines": ls})

    role_setters = []
    setters = blocks(src, FUNCTION)
    target_of = {}
    for f in setters:
        for m in re.finditer(r"\b(_?[A-Za-z]\w*)\s*=\s*([^;]+);", f["body"]):
            var, rhs = m.group(1), m.group(2)
            if re.match(r"^_(?:mbr|usdtPair|user|mod|adm|miu)$|^naming$", var):
                target_of[var] = f
        if ROLE_FN.match(f["name"]):
            refs = sorted({r for r in ("_mbr", "_usdtPair", "_user", "_mod", "_adm", "_miu", "naming", "owner")
                           if r in f["header"] + f["body"]})
            role_setters.append({"function": f["name"], "line": f["line"], "guard_refs": refs,
                                 "writes": [m.group(1) for m in re.finditer(r"\b(_?[A-Za-z]\w*)\s*=\s*[^;]+;", f["body"])
                                            if m.group(1) in ("_mbr", "_usdtPair", "_user", "_mod", "_adm", "_miu", "naming")]})
    chains = []
    for s in role_setters:
        for ref in s["guard_refs"]:
            if ref in target_of and target_of[ref]["name"] != s["function"]:
                chains.append({"from_role": ref, "via": target_of[ref]["name"], "to_function": s["function"],
                               "to_line": s["line"]})

    fee_caps = [{"line": lineno(src, m.start()), "variable": m.group(1), "ceiling": int(m.group(2))}
                for m in FEE_CAP.finditer(src)]
    renounce = [{"line": f["line"], "function": f["name"]}
                for f in setters if f["name"] == "renounceOwnership"]
    renounce_calls = [{"line": lineno(src, m.start()), "call": m.group(0)}
                      for m in re.finditer(r"\brenounceOwnership\s*\(\s*\)", src)]

    sell_gates = [{"line": lineno(src, m.start()), "expression": re.sub(r"\s+", " ", m.group(0))}
                  for m in re.finditer(r"require\s*\([^;]{0,120}(?:allow\s*\[|isBlacklisted\s*\[|blacklists\s*\[|ensure\s*\(|canSale\s*\[)[^;]{0,120}\)", src)]

    return {
        "file": name,
        "pragma": (re.search(r"pragma\s+solidity\s+([^;]+);", src).group(1).strip()
                   if re.search(r"pragma\s+solidity\s+([^;]+);", src) else None),
        "contracts": re.findall(r"\bcontract\s+([A-Za-z_]\w*)", src),
        "decimal_address_literals": decimals,
        "hex_address_literals": hexes,
        "address_assembled_from_fragments": fragments,
        "modifiers_with_hardcoded_address": mods,
        "msgsender_ne_function_guards": neg,
        "balance_overwrites": bal_writes,
        "double_credit_helpers": double,
        "role_chain_setters": role_setters,
        "role_chain_edges": chains,
        "transfer_gating_requires": sell_gates,
        "fee_cap_100": [c for c in fee_caps if c["ceiling"] == 100],
        "fee_caps_all": fee_caps,
        "renounceOwnership": renounce,
        "renounce_calls": renounce_calls,
        "uups": "UUPSUpgradeable" in src or "_authorizeUpgrade" in src,
        "initialize": [{"line": f["line"], "visibility": f["header"].split(")")[-1].strip()}
                       for f in setters if f["name"] == "initialize"],
        "disable_initializers": "_disableInitializers" in src,
    }


def render(rows: list[dict]) -> str:
    out = []
    for r in rows:
        out.append(f"\n== {r['file']} ==")
        out.append(f"  pragma: {r['pragma']}  contracts: {', '.join(r['contracts'])}")
        for key in ("decimal_address_literals", "hex_address_literals", "address_assembled_from_fragments",
                    "modifiers_with_hardcoded_address", "msgsender_ne_function_guards", "balance_overwrites",
                    "double_credit_helpers", "role_chain_setters", "role_chain_edges",
                    "transfer_gating_requires", "fee_cap_100", "renounceOwnership", "renounce_calls"):
            val = r[key]
            out.append(f"  {key}: {len(val)}")
            for item in val:
                out.append("    - " + json.dumps(item, ensure_ascii=False, sort_keys=True))
        out.append(f"  uups: {r['uups']}; initialize: {r['initialize']}; disable_initializers: {r['disable_initializers']}")
    return "\n".join(out).lstrip()


def main(argv: list[str]) -> int:
    as_json = "--json" in argv
    out_file = None
    if "--out" in argv:
        i = argv.index("--out")
        out_file = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    paths = []
    for a in argv:
        if a.startswith("--"):
            continue
        p = pathlib.Path(a)
        paths.extend(sorted(p.rglob("*.sol"))) if p.is_dir() else paths.append(p)
    rows = [scan_text(p.read_text(encoding="utf-8", errors="replace"), p.as_posix()) for p in paths]
    if as_json:
        text = json.dumps(rows, indent=2, ensure_ascii=False)
    else:
        text = render(rows)
    if out_file:
        pathlib.Path(out_file).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
