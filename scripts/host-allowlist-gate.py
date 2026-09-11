#!/usr/bin/env python3
"""Refuse a tracked file that references a host or an address this repository does not publish.

This bundle was derived from a working tree that is not published, and the
derivation deleted every reference to a host, a path and an internal identifier
belonging to that tree. A deletion holds for exactly as long as nobody puts one
back, and the way one comes back is not a decision: it is a paragraph copied
across, a comment restored from an older revision, a generator whose header still
carries the URL it was written under.

So the check here is a POSITIVE one. Every hostname any tracked file mentions must
appear in the allowlist below, and every local filesystem path and mail address is
refused outright. A negative check would have to spell the strings it forbids,
which puts them in the repository that must not carry them; this one never names
anything it is protecting against, and it catches a host nobody thought to forbid.

    scripts/host-allowlist-gate.py
    scripts/host-allowlist-gate.py --list      # what was seen, and how often

Exit codes:
    0  every referenced host is on the allowlist and no local path or address
       appears
    1  at least one reference is not allowed; each is printed with its file, its
       line number and the line
    2  could not check: this is not a git checkout, or `git ls-files` returned
       nothing, which is a broken read and never a clean one
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent

# Hosts this repository is allowed to name. Add one only when the repository
# genuinely references it, and never to make a failure go away.
ALLOWED_HOSTS = frozenset(
    {
        # the predicate and its home
        "in-toto.io",
        "github.com",
        "raw.githubusercontent.com",
        "doi.org",
        "orcid.org",
        # the engines
        "openpolicyagent.org",
        "www.openpolicyagent.org",
        "kyverno.io",
        "policies.kyverno.io",
        "release.kyverno.io",
        "policy.sigstore.dev",
        "sigstore.dev",
        "www.sigstore.dev",
        "cuelang.org",
        "cue-lang.org",
        # kubernetes api groups and schema hosts that appear in manifests
        "kubernetes.io",
        "apps.kubernetes.io",
        "json-schema.org",
        # license and citation
        "www.apache.org",
        "apache.org",
        "citation-file-format.github.io",
        # the specification vocabulary
        "www.w3.org",
        "www.rfc-editor.org",
        "datatracker.ietf.org",
        # a registry host in a sample manifest, and the reserved TLD the rego
        # tests use for a predicate type that must not resolve to anything
        "ghcr.io",
        "example.invalid",
    }
)

URL_RE = re.compile(r"\b(?:https?|ftp)://([A-Za-z0-9._~%-]+(?::[0-9]+)?)")
# A bare hostname carrying a public suffix, outside a URL. Deliberately narrow:
# it must have at least two labels and end in letters, so version strings, file
# names and digests do not register as hosts.
BARE_HOST_RE = re.compile(
    r"(?<![A-Za-z0-9@._/-])"
    r"((?:[a-z0-9][a-z0-9-]*\.)+(?:dev|com|io|org|net|ai|app|sh|cloud|xyz|co))"
    r"(?![A-Za-z0-9_-])"
)
MAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
LOCAL_PATH_RE = re.compile(r"(?<![A-Za-z0-9])(?:/home/|/Users/|/mnt/|/blue/|~/)")

# File names, not hosts. A bare-host match against one of these is the regex
# being too eager rather than a reference, so they are removed before matching.
NOT_A_HOST = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:json|yaml|yml|md|py|rego|cff|txt|pub|sh|toml|lock|cfg|ini|ts|go|mod|sum)\b"
)

# Where the allowlist itself lives, plus anything binary enough that a line is
# not a meaningful unit. The allowlist file is skipped because a list of allowed
# hosts is a list of hosts, and checking it against itself measures nothing.
SKIP = {"scripts/host-allowlist-gate.py"}

# A citation file carries the author's address because the format requires one,
# and a repository with no contact is worse than one with a personal address. So
# the address is permitted THERE and nowhere else, and its domain is still
# checked: the failure this whole file guards against is an organisational
# address arriving where a personal one belongs.
MAIL_ALLOWED_IN = {"CITATION.cff"}
MAIL_ALLOWED_DOMAINS = frozenset({"gmail.com"})
BINARYISH_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".gz", ".zip"}


def cannot(msg: str) -> None:
    print(f"host-allowlist-gate: COULD NOT CHECK -- {msg}", file=sys.stderr)
    raise SystemExit(2)


def tracked_files() -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=HERE,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        cannot(f"could not run git: {exc}")
    if proc.returncode != 0:
        cannot(f"git ls-files exited {proc.returncode}: {proc.stderr.decode().strip()}")
    names = [n for n in proc.stdout.decode("utf-8").split("\0") if n]
    if not names:
        cannot(
            "git ls-files listed no files. A repository of zero files passes every "
            "check here vacuously, which is why an empty listing is a refusal."
        )
    return names


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print every host seen")
    args = parser.parse_args(argv[1:])

    problems: list[str] = []
    seen: Counter[str] = Counter()
    scanned = 0

    for name in tracked_files():
        if name in SKIP or Path(name).suffix.lower() in BINARYISH_SUFFIXES:
            continue
        path = HERE / name
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        scanned += 1
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = NOT_A_HOST.sub(" ", line)
            hosts = {m.group(1).split(":")[0].lower() for m in URL_RE.finditer(line)}
            hosts |= {m.group(1).lower() for m in BARE_HOST_RE.finditer(stripped)}
            for host in hosts:
                seen[host] += 1
                if host not in ALLOWED_HOSTS:
                    problems.append(f"{name}:{lineno}: host {host!r} is not allowed: {line.strip()}")
            for m in MAIL_RE.finditer(line):
                address = m.group(0)
                domain = address.rsplit("@", 1)[1].lower()
                if name in MAIL_ALLOWED_IN and domain in MAIL_ALLOWED_DOMAINS:
                    continue
                problems.append(f"{name}:{lineno}: mail address {address!r}: {line.strip()}")
            if LOCAL_PATH_RE.search(line):
                problems.append(f"{name}:{lineno}: local filesystem path: {line.strip()}")

    if args.list:
        for host, count in sorted(seen.items(), key=lambda kv: (-kv[1], kv[0])):
            mark = " " if host in ALLOWED_HOSTS else "!"
            print(f"{mark} {count:5d}  {host}")

    if problems:
        for p in problems:
            print(p, file=sys.stderr)
        print(
            f"\nhost-allowlist-gate: {len(problems)} disallowed reference(s) across "
            f"{scanned} tracked file(s).",
            file=sys.stderr,
        )
        return 1

    print(
        f"host-allowlist-gate: {scanned} tracked file(s), {len(seen)} distinct host(s), "
        f"every one on the allowlist, no mail address and no local path."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
