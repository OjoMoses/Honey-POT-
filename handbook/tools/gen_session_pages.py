#!/usr/bin/env python3
"""Generate docs/contracts pages from the single fact table.

Usage:
    python -I gen_session_pages.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from contract_facts import SESSIONS

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "contracts"
COPY_ROOT = ROOT / "contracts"

REQUIRED = (
    "id", "slug", "dir", "file", "title", "classification", "verdict",
    "confidence", "pragma", "lines", "sha256", "summary", "user_experience",
    "control", "primitives", "paths", "invariants", "numbers", "signals",
    "tests", "limits", "errata", "related",
)


def validate() -> None:
    seen = set()
    for s in SESSIONS:
        missing = [k for k in REQUIRED if k not in s]
        if missing:
            raise SystemExit(f"session {s.get('id')}: missing {missing}")
        if s["id"] in seen:
            raise SystemExit(f"duplicate session id {s['id']}")
        seen.add(s["id"])
        if len(s["sha256"]) != 64:
            raise SystemExit(f"session {s['id']}: bad sha256")
        copy = COPY_ROOT / s["dir"] / s["file"]
        if copy.exists():
            got = hashlib.sha256(copy.read_bytes()).hexdigest()
            if got != s["sha256"]:
                raise SystemExit(f"session {s['id']}: hash mismatch for {copy}")
    for s in SESSIONS:
        for rel in s["related"]:
            if rel not in seen:
                raise SystemExit(f"session {s['id']}: bad related id {rel}")


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |"]
    out.append("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        out.append("| " + " | ".join(str(x).replace("|", "\\|") for x in row) + " |")
    return "\n".join(out)


def render(s: dict, by_id: dict[str, dict]) -> str:
    src_rel = f"../../contracts/{s['dir']}/{s['file']}"
    # Keep the signal table compact and honest: each signal is an indicator,
    # not a verdict. Signals already containing inline code are left alone so
    # that multiple code spans are not nested inside one another.
    signal_rows = []
    for x in s["signals"]:
        cell = x if "`" in x else f"`{x}`"
        signal_rows.append([cell, "Read the cited source path before treating this as malicious."])

    control_rows = [[x["actor"], x["authority"], x["evidence"], x["reachability"]] for x in s["control"]]
    primitive_rows = [[x["name"], x["location"], x["effect"], x["why"]] for x in s["primitives"]]
    path_rows = [[x["function"], x["gate"], x["effect"], x["evidence"]] for x in s["paths"]]

    related = []
    for rid in s["related"]:
        t = by_id[rid]
        related.append(f"- [Session {t['id']} — {t['title']}]({t['slug']}.md)")

    lines = []
    lines.append(f"# Session {s['id']} — {s['title']}")
    lines.append("")
    lines.append("[Back to the contract index](index.md) · [Handbook home](../../README.md)")
    lines.append("")
    lines.append(f"> **Classification:** {s['classification']}  ")
    lines.append(f"> **Verdict:** `{s['verdict']}`  ")
    lines.append(f"> **Confidence:** {s['confidence']}  ")
    lines.append("> **Method:** source review and static scanning only. No compiler, fork, or live deployment was available.")
    lines.append("")
    lines.append("## At a glance")
    lines.append("")
    lines.append(md_table(
        ["Field", "Value"],
        [
            ["Source", f"[`{s['dir']}/{s['file']}`]({src_rel})"],
            ["Pragma", f"`{s['pragma']}`"],
            ["Lines", str(s["lines"])],
            ["SHA-256", f"`{s['sha256']}`"],
            ["Family", s["classification"]],
            ["Page generator", "`tools/gen_session_pages.py` from `tools/contract_facts.py`"],
        ],
    ))
    lines.append("")
    lines.append(s["summary"])
    lines.append("")
    lines.append("## What a user experiences")
    lines.append("")
    lines.append(s["user_experience"])
    lines.append("")
    lines.append("## Control plane")
    lines.append("")
    lines.append("The table records who can do what, where the gate is, and how the actor is reached. "
                 "A hard-coded address is not automatically the deployer; verify the key's ownership "
                 "outside this repository before drawing a real-world attribution.")
    lines.append("")
    lines.append(md_table(["Actor", "Authority", "Source evidence", "Reachability"], control_rows))
    lines.append("")
    lines.append("## Primitives that create the trap")
    lines.append("")
    lines.append(md_table(["Primitive", "Location", "Effect", "Why it matters"], primitive_rows))
    lines.append("")
    lines.append("## Privileged and accounting paths")
    lines.append("")
    lines.append("Line numbers refer to the copied source linked above. `A`, `B`, `C`, `D`, and `P` "
                 "are the address labels defined in [the control-plane analysis](../analysis/control-plane.md).")
    lines.append("")
    lines.append(md_table(["Function / path", "Gate", "Effect", "Evidence"], path_rows))
    lines.append("")
    lines.append("## Ledger and invariant notes")
    lines.append("")
    for x in s["invariants"]:
        lines.append(f"- {x}")
    lines.append("")
    lines.append("## Arithmetic notes")
    lines.append("")
    for x in s["numbers"]:
        lines.append(f"- {x}")
    lines.append("")
    lines.append("These are source-level examples. See [`math.md`](../reference/math.md) and the "
                 "reproducible transcript in [`reports/verification.txt`](../../reports/verification.txt) "
                 "for exact integer checks.")
    lines.append("")
    lines.append("## Detection signals")
    lines.append("")
    lines.append(md_table(["Signal", "Interpretation"], signal_rows))
    lines.append("")
    lines.append("## Verification plan (not run)")
    lines.append("")
    lines.append("The following tests are proposed. They are not evidence that the behavior was observed on-chain.")
    lines.append("")
    for x in s["tests"]:
        lines.append(f"1. {x}")
    lines.append("")
    lines.append("## Limits and open questions")
    lines.append("")
    for x in s["limits"]:
        lines.append(f"- {x}")
    if s["verdict"] == "clean":
        lines.append("- A clean verdict here means no hidden-control primitive was found in this file. "
                     "It is not a guarantee of economic safety, liquidity safety, or compiler/runtime equivalence.")
    lines.append("")
    lines.append("## Errata for prior documentation")
    lines.append("")
    for x in s["errata"]:
        lines.append(f"- {x}")
    lines.append("")
    lines.append("See the consolidated [errata page](../analysis/errata.md) for repository-wide corrections.")
    lines.append("")
    if related:
        lines.append("## Related sessions")
        lines.append("")
        lines.extend(related)
        lines.append("")
    lines.append("## Source")
    lines.append("")
    lines.append(f"The handbook copy is [`contracts/{s['dir']}/{s['file']}`]({src_rel}); "
                 f"its SHA-256 is `{s['sha256']}`. The repository copy at the same relative "
                 f"path (`contracts/{s['dir']}/{s['file']}`) is byte-identical, and the "
                 f"generator fails if the hash ever differs.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Generated from the fact table. Do not edit this page by hand; edit "
                 "`tools/contract_facts.py` and rerun the generator.")
    lines.append("")
    return "\n".join(lines)


def render_index() -> str:
    counts = {"malicious": 0, "broken": 0, "clean": 0}
    for s in SESSIONS:
        counts[s["verdict"]] += 1
    rows = []
    for s in SESSIONS:
        rows.append([
            f"[{s['id']}]({s['slug']}.md)",
            s["title"],
            f"`{s['pragma']}`",
            s["classification"],
            f"`{s['verdict']}`",
        ])
    lines = []
    lines.append("# Contract reference index")
    lines.append("")
    lines.append("[Handbook home](../../README.md) · [Detection playbook](../guides/detection-playbook.md) · "
                 "[Taxonomy](../reference/taxonomy.md)")
    lines.append("")
    lines.append("This index and every page under `docs/contracts/` are generated from "
                 "`tools/contract_facts.py` by `tools/gen_session_pages.py`.")
    lines.append("")
    lines.append(f"- `malicious`: **{counts['malicious']}**")
    lines.append(f"- `broken`: **{counts['broken']}**")
    lines.append(f"- `clean` (source scope): **{counts['clean']}**")
    lines.append("")
    lines.append("The `broken` label is not a safety endorsement. It means dangerous hidden-control "
                 "patterns are present and the code also contains an internal defect that changes the "
                 "intended path (for example, a `buy()` that never pays ETH or an initializer that "
                 "double-counts supply).")
    lines.append("")
    lines.append(md_table(["Session", "Short title", "Pragma", "Classification", "Verdict"], rows))
    lines.append("")
    lines.append("## Reading order for a defender")
    lines.append("")
    lines.append("1. Read [taxonomy](../reference/taxonomy.md) to separate bait, exit gates, and accounting bugs.")
    lines.append("2. Read [control-plane](../analysis/control-plane.md) for the A/B/C/D/P address map and role chains.")
    lines.append("3. Read the session pages for the contracts in scope.")
    lines.append("4. Use the [detection playbook](../guides/detection-playbook.md) and the scanner output in "
                 "[`reports/scan.txt`](../../reports/scan.txt).")
    lines.append("5. Read [errata](../analysis/errata.md) before trusting the older `docs/` tree or the `out/` directory.")
    lines.append("")
    lines.append("## Scope boundary")
    lines.append("")
    lines.append("No Solidity compiler was available. Pages describe source semantics and static indicators; "
                 "they do not certify bytecode, proxy storage, or live liquidity. No deployment, transaction, "
                 "mempool, or fork execution was performed.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    validate()
    OUT.mkdir(parents=True, exist_ok=True)
    by_id = {s["id"]: s for s in SESSIONS}
    for s in SESSIONS:
        path = OUT / f"{s['slug']}.md"
        path.write_text(render(s, by_id), encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    index = OUT / "index.md"
    index.write_text(render_index(), encoding="utf-8")
    print(f"wrote {index.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
