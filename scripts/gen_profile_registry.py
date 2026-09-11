#!/usr/bin/env python3
"""Render PROFILE-REGISTRY.md from the vendored obligation registry and the maps.

The registry is the closed set of obligations a consumer of this evidence can be
asked to enforce. It is not written here and it is not typed anywhere: every row
comes from `registry/conditions.json`, which `scripts/gen_condition_registry.py`
vendors from the conformance corpus's own condition table, and every disposition
comes from a rail's PROFILE-MAP.json, which is measured.

    scripts/gen_profile_registry.py
    scripts/gen_profile_registry.py --check

Exit codes:
    0  written, or under --check the file matches what this renders
    1  under --check, the file is stale
    2  could not render: the registry or a map is missing. Never a pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
REGISTRY = HERE / "registry" / "conditions.json"
PROFILES = HERE / "profiles"
OUT = HERE / "PROFILE-REGISTRY.md"

MARK = {"enforced": "enforced", "approximated": "approx", "unreachable": "unreachable"}


def cannot(msg: str) -> None:
    print(f"gen_profile_registry: COULD NOT RENDER -- {msg}", file=sys.stderr)
    raise SystemExit(2)


def render() -> str:
    if not REGISTRY.is_file():
        cannot(f"missing {REGISTRY}")
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    obligations = registry["conditions"]
    if not obligations:
        cannot(f"{REGISTRY} carries no obligations")

    maps: dict[str, dict] = {}
    for path in sorted(PROFILES.glob("*/PROFILE-MAP.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        maps[doc["rail"]] = doc["obligations"]
    if not maps:
        cannot(f"no PROFILE-MAP.json under {PROFILES}")

    rails = sorted(maps)
    src = registry["source"]
    lines: list[str] = []
    lines.append("# Profile registry: what each rail enforces\n")
    lines.append(
        f"{len(obligations)} obligations, {len(rails)} rails, and one row per pair. "
        f"Every disposition below is measured by `scripts/gen_profile_map.py` from a "
        f"live run of every rail over this bundle's corpus projection, and "
        f"`scripts/profile-map-gate.py` refuses a map that claims more than the "
        f"measurement supports.\n"
    )
    lines.append(
        f"Corpus digest `{src['corpusDigest'][:12]}`, predicate type "
        f"`{src['predicateType']}`. Re-derive the registry with "
        f"`{src['derived_by']}` and this document with "
        f"`scripts/gen_profile_registry.py`.\n"
    )
    lines.append("## What the three dispositions mean\n")
    lines.append(
        "**enforced** the rail matched the oracle on every vector citing the "
        "obligation, and the map names a rule in that rail's own artifact that the "
        "gate opens the artifact and finds. A rail that answers differently from the "
        "oracle on any vector citing an obligation may not carry this value, and the "
        "gate makes that a hard error.\n"
    )
    lines.append(
        "**approx** the rail matched the oracle on every vector citing the "
        "obligation and no rule has been named for it. This is the default for a rail "
        "that behaves correctly, because agreement on the vectors that happen to exist "
        "is a weaker claim than a named rule. Promoting a row costs one line in "
        "`profiles/rule-index.json`.\n"
    )
    lines.append(
        "**unreachable** the rail is not shown to enforce the obligation here, and the "
        "row names an obstruction from a closed vocabulary saying which of the two "
        "reasons applies: the rail answers differently from the oracle on a vector "
        "citing the obligation, or no vector citing it appears in this projection at "
        "all. The second is a gap in what has been measured and says nothing about the "
        "rail, which is why it has its own value and is never folded into the first.\n"
    )

    counts = {
        rail: {d: 0 for d in ("enforced", "approximated", "unreachable")} for rail in rails
    }
    for rail in rails:
        for row in maps[rail].values():
            counts[rail][row["disposition"]] += 1

    lines.append("## Totals\n")
    lines.append("| rail | enforced | approx | unreachable |")
    lines.append("|---|---|---|---|")
    for rail in rails:
        c = counts[rail]
        lines.append(
            f"| `{rail}` | {c['enforced']} | {c['approximated']} | {c['unreachable']} |"
        )
    lines.append("")

    lines.append("## The obligations\n")
    lines.append(
        "| obligation | spec anchor | condition | "
        + " | ".join(f"`{r}`" for r in rails)
        + " |"
    )
    lines.append("|---|---|---|" + "---|" * len(rails))
    for ob in obligations:
        cells = []
        for rail in rails:
            row = maps[rail].get(ob["id"])
            if row is None:
                cells.append("MISSING")
                continue
            mark = MARK[row["disposition"]]
            if row["disposition"] == "unreachable":
                mark = f"{mark} ({row.get('obstruction', 'unnamed')})"
            elif row["disposition"] == "enforced":
                mark = f"{mark} ({row.get('rule', 'unnamed')})"
            cells.append(mark)
        text = ob["text"].replace("|", "\\|")
        lines.append(
            f"| `{ob['id']}` | {ob['anchor']} | {text} | " + " | ".join(cells) + " |"
        )
    lines.append("")
    lines.append(
        "A row reading `unreachable (no-vector-in-projection)` is a hole in the "
        "measurement, not a finding about the rail. Closing one means adding a vector "
        "that forces the obligation, which is work in the conformance corpus rather "
        "than work here.\n"
    )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv[1:])
    rendered = render()
    if args.check:
        if not OUT.is_file():
            print(f"{OUT} does not exist", file=sys.stderr)
            return 1
        if OUT.read_text(encoding="utf-8") != rendered:
            print(f"{OUT} is stale against the registry and the maps", file=sys.stderr)
            return 1
        print("check: PROFILE-REGISTRY.md is current")
        return 0
    OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUT.relative_to(HERE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
