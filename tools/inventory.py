#!/usr/bin/env python3
"""Inventory and duplicate comparison evidence (standard library only).

Produces two reports:
  * inventory: SHA-256 prefix, size and relative path for every contract-like file
  * duplicates: raw, LF-normalised and comment-stripped comparison of session files

Usage:
    python3 -I tools/inventory.py <rootA> <rootB> [--ca rootA/contracts] \
        [--cb rootB/out/contracts] --inv reports/inventory.txt --dup reports/duplicates.txt
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import sys


def collect(root: pathlib.Path, tag: str) -> list[tuple[str, str, str, int]]:
    rows = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "__pycache__")]
        for fn in fns:
            path = pathlib.Path(dp) / fn
            ext = path.suffix
            if ext != ".sol" and not (ext == "" and not fn.startswith(".")):
                continue
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()[:16]
            rows.append((digest, tag, str(path.relative_to(root)).replace("\\", "/"), len(data)))
    return rows


def strip_comments(s: str) -> str:
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    return re.sub(r"//[^\n]*", "", s)


def compact(s: str) -> str:
    return re.sub(r"\s+", "", strip_comments(s))


def main(argv: list[str]) -> int:
    args = argv[:]
    def take(flag: str) -> str | None:
        if flag in args:
            i = args.index(flag)
            v = args[i + 1]
            del args[i:i + 2]
            return v
        return None

    inv = take("--inv") or "reports/inventory.txt"
    dup = take("--dup") or "reports/duplicates.txt"
    ca_val = take("--ca")
    cb_val = take("--cb")
    if len(args) < 2:
        print(__doc__)
        return 2
    a, b = pathlib.Path(args[0]), pathlib.Path(args[1])
    ca = pathlib.Path(ca_val) if ca_val else a / "contracts"
    cb = pathlib.Path(cb_val) if cb_val else b / "out" / "contracts"

    rows = collect(a, "A") + collect(b, "B")
    rows.sort()
    inv_text = [f"Inventory root A: {a}", f"Inventory root B: {b}",
                f"Files: {len(rows)}", "", "sha256[:16]  root  bytes  relative path", ""]
    inv_text += [f"{h}  {tag}  {n:7}  {rel}" for h, tag, rel, n in rows]
    pathlib.Path(inv).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(inv).write_text("\n".join(inv_text) + "\n", encoding="utf-8")

    dup_text = [f"Duplicate comparison: {ca} vs {cb}", "",
                "file: raw lengths A/B; compact (comments+whitespace removed) lengths A/B; "
                "LF-normalised bytes equal; CRLF counts A/B", ""]
    for sub in ("honeypot", "token"):
        da, db = ca / sub, cb / sub
        if not da.is_dir() or not db.is_dir():
            continue
        for fn in sorted(p.name for p in da.glob("*.sol")):
            pa, pb = da / fn, db / fn
            if not pb.exists():
                dup_text.append(f"{fn}: MISSING in root B")
                continue
            ra, rb = pa.read_bytes(), pb.read_bytes()
            compact_a = compact(ra.decode("utf-8", "replace"))
            compact_b = compact(rb.decode("utf-8", "replace"))
            lf = ra.replace(b"\r\n", b"\n") == rb.replace(b"\r\n", b"\n")
            dup_text.append(f"{fn}: raw {len(ra)}/{len(rb)}; compact {len(compact_a)}/{len(compact_b)}; "
                            f"LF-normalised identical={lf}; code-identical={compact_a == compact_b}; "
                            f"CRLF {ra.count(bytes([13,10]))}/{rb.count(bytes([13,10]))}")
    pathlib.Path(dup).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(dup).write_text("\n".join(dup_text) + "\n", encoding="utf-8")
    print(f"wrote {inv} ({len(rows)} files) and {dup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
