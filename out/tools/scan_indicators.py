#!/usr/bin/env python3
"""Static indicator scanner for token-contract review (defensive tooling).

Flags code patterns that frequently accompany hidden-privilege / honeypot
tokens. It is a triage aid, not a verdict: every hit needs manual review.

Usage:  python3 -I scan_indicators.py <file.sol|dir> [...] [--json]
"""
import json, re, sys, pathlib

def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)

DEC_ADDR   = re.compile(r"address\s*\(\s*(\d{20,})\s*\)")
HEX_ADDR   = re.compile(r"address\s*\(\s*(0x[0-9a-fA-F]{40})\s*\)")
SHIFT_ASM  = re.compile(r"uint160\s*\([^)]*\)\s*<<\s*(?:128|96|64|32)")
DIRECT_SET = re.compile(r"\b((?:balances?|_balances|balanceOf)\s*\[[^\]]+\])\s*=\s*(?!=)([^;]+);")
DOUBLE_CR  = re.compile(r"(\w+\[(\w+)\])\s*\+=\s*(\w+)\s*;\s*emit\s+Transfer\s*\(\s*address\(0\)\s*,\s*\2\s*,\s*\3\s*\)\s*;\s*\1\s*\+=\s*\3", re.S)
DEX_GUARD  = re.compile(r"require\s*\(\s*msg\.sender\s*!=\s*(\w+)\s*\(\s*\)\s*\)")
ROLE_FNS   = ("setMember", "setUser", "setMod", "setAdm", "setUsdtPair")
SELL_GATE  = re.compile(r"require\s*\(\s*allow\[\s*_from\s*\]\s*==\s*true\s*\)|require\s*\(\s*ensure\s*\(|require\s*\(\s*!\s*isBlacklisted\[")
FEE_100    = re.compile(r"Fee\s*<=\s*100")
RENOUNCE   = re.compile(r"function\s+renounceOwnership")

def to_hex(n: int) -> str:
    return "0x%040x" % n

def modifier_bodies(src):
    for m in re.finditer(r"modifier\s+(\w+)\s*\([^)]*\)\s*\{(.*?)\n\s*\}", src, re.S):
        yield m.group(1), m.group(2)

def scan(path: pathlib.Path) -> dict:
    raw = path.read_text(encoding="utf8", errors="replace")
    src = strip_comments(raw)
    flat = re.sub(r"\s+", " ", src)
    dec = sorted({to_hex(int(n)) for n in DEC_ADDR.findall(src) if int(n) < 2**160})
    hexa = sorted({h.lower() for h in HEX_ADDR.findall(src)})
    priv_mods = []
    for name, body in modifier_bodies(src):
        b = re.sub(r"\s+", " ", body)
        if DEC_ADDR.search(b):
            priv_mods.append(name)
    guards = sorted({g for g in DEX_GUARD.findall(src)})
    return {
        "file": str(path),
        "decimal_address_literals": dec,
        "hex_address_literals": hexa,
        "address_assembled_from_fragments": bool(SHIFT_ASM.search(src)),
        "modifiers_with_hardcoded_address": priv_mods,
        "msgsender_ne_function_guards": guards,
        "balance_overwrites": sum(1 for _, rhs in DIRECT_SET.findall(flat)
                                  if not re.search(r"[-+]|\.sub\(|\.add\(|^\s*_?totalSupply\s*$|^\s*0\s*$", rhs)),
        "double_credit_helpers": len(DOUBLE_CR.findall(flat)),
        "role_chain_setters": [f for f in ROLE_FNS if re.search(r"function\s+%s\b" % f, src)],
        "transfer_gating_requires": len(SELL_GATE.findall(flat)),
        "fee_cap_is_100_percent": bool(FEE_100.search(src)),
        "has_renounceOwnership": bool(RENOUNCE.search(src)),
        "upgradeable_uups": "UUPSUpgradeable" in src,
    }

def main(argv):
    as_json = "--json" in argv
    paths = []
    for a in argv:
        if a.startswith("--"): continue
        p = pathlib.Path(a)
        paths += sorted(p.rglob("*.sol")) if p.is_dir() else [p]
    rows = [scan(p) for p in paths]
    if as_json:
        print(json.dumps(rows, indent=2)); return
    for r in rows:
        print(f"\n{r['file']}")
        for k, v in r.items():
            if k != "file": print(f"  {k}: {v}")

if __name__ == "__main__":
    main(sys.argv[1:])
