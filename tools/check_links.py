#!/usr/bin/env python3
"""Markdown link and anchor checker (standard library only).

Checks relative file links and in-page/target anchors against headings using
GitHub-style slugs. External http(s) links are counted but not fetched.

Usage:
    python3 -I tools/check_links.py [root] [--out FILE]
"""
from __future__ import annotations

import pathlib
import re
import sys

LINK_RE = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
IGNORE_DIRS = {".git", "__pycache__", "reports-out"}


def slug(text: str) -> str:
    """GitHub-style heading anchor."""
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\*\*([^*]*)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]*)\*", r"\1", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"\s", "-", text)


def anchors(path: pathlib.Path) -> set[str]:
    if not path.exists() or path.suffix.lower() != ".md":
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = HEADING_RE.match(line)
        if m:
            out.add(slug(m.group(2)))
    return out


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[0] if argv and not argv[0].startswith("--") else ".")
    out_file = None
    if "--out" in argv:
        i = argv.index("--out")
        out_file = pathlib.Path(argv[i + 1])

    files = [p for p in sorted(root.rglob("*.md")) if not (set(p.parts) & IGNORE_DIRS)]
    broken: list[str] = []
    lines: list[str] = []
    internal = external = anchor_checks = 0

    for md in files:
        text = md.read_text(encoding="utf-8", errors="replace")
        anchor_cache: dict[pathlib.Path, set[str]] = {}
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in LINK_RE.finditer(line):
                dest = m.group(1)
                if dest.startswith(("http://", "https://", "mailto:")):
                    external += 1
                    continue
                if dest.startswith("#"):
                    target, frag = md, dest[1:]
                else:
                    raw = dest.split("#", 1)[0]
                    target = (md.parent / raw).resolve()
                    frag = dest.split("#", 1)[1] if "#" in dest else None
                    internal += 1
                    if not target.exists():
                        broken.append(f"BROKEN FILE  {md.relative_to(root)}:{lineno} -> {dest}")
                        continue
                if frag:
                    anchor_checks += 1
                    if target not in anchor_cache:
                        anchor_cache[target] = anchors(target)
                    if frag not in anchor_cache[target]:
                        broken.append(f"BROKEN ANCHOR {md.relative_to(root)}:{lineno} -> {dest} "
                                      f"(available: {sorted(anchor_cache[target])[:8]})")

    lines.append(f"Markdown files checked: {len(files)}")
    lines.append(f"Internal file links checked: {internal}")
    lines.append(f"Anchor links checked: {anchor_checks}")
    lines.append(f"External links counted (not fetched): {external}")
    lines.append(f"Broken links: {len(broken)}")
    lines.extend(broken)
    report = "\n".join(lines) + "\n"
    print(report, end="")
    if out_file:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(report, encoding="utf-8")
    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
