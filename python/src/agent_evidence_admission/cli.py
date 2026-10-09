"""Command line: ``agent-evidence-admission digest-check <document> <artifact>``.

Exit 0 when the artifact has a digest the document names, 1 when it does not (or the document
names none), 2 when the document or the artifact could not be read.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .digest_check import check, parse_document, read_source


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-evidence-admission")
    parser.add_argument("--version", action="version", version=f"agent-evidence-admission {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    digest = commands.add_parser(
        "digest-check",
        help="check that an artifact has a digest its document (TEA, CycloneDX, in-toto) names",
    )
    digest.add_argument("document", help="path or https URL of the document that names the digest")
    digest.add_argument("artifact", help="path or https URL of the artifact the document covers")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        document = parse_document(read_source(args.document))
        artifact = read_source(args.artifact)
    except (OSError, ValueError) as error:
        print(f"ERROR could not read: {error}", file=sys.stderr)
        return 2
    result = check(document, artifact)
    if result.ok and result.matched:
        algorithm, value = result.matched
        print(f"PASS {args.artifact} has {algorithm}:{value}, named in {args.document}")
        return 0
    named = ", ".join(f"{a}:{v}" for a, v in result.declared) or "nothing"
    print(f"FAIL {result.reason}: {args.document} names {named}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
