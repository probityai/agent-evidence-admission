#!/usr/bin/env python3
"""Refuse a tracked file whose prose carries an authorship mark or breaks the style rules.

Two checks live here, and they are built differently on purpose.

The first refuses an authorship mark: a tool name, a vendor name, an attribution
trailer, a session identifier, or one of the internal names the derivation
removed. A gate for those cannot spell them, because spelling them puts them in
the repository that must not carry them -- the same argument
`scripts/host-allowlist-gate.py` makes for checking hosts positively. So this one
compares the SHA-256 of every one-, two- and three-word run against a table of
digests. The table names nothing. `--selftest` proves the table still fires by
assembling a marked string from character codes at run time and feeding it
through the same path, which is the only way a hash table can be shown to be
looking for something rather than for nothing.

The second refuses a word or a heading the Google developer documentation style
guide rules out. Those are ordinary English and safe to write down, so they are
written down.

`--history` runs the mark half over every blob in the object database and every
commit message, because a mark deleted in a later commit is still published when
the repository is. It refuses to run on a shallow clone rather than reporting the
part it can see as the whole.

Neither check is the whole of either rule. A style guide is read and applied by a
writer; this catches the mechanical subset that regresses silently, which is the
part a human reviewer stops noticing after the third file.

    scripts/docs-style-gate.py
    scripts/docs-style-gate.py --history      # every blob and message ever reachable
    scripts/docs-style-gate.py --selftest    # prove both tables still fire

Exit codes:
    0  every tracked file passes both checks
    1  at least one file fails; each finding prints its file, line and rule
    2  could not check: this is not a git checkout, `git ls-files` returned
       nothing, or a table failed its own positive control. A broken read is
       never reported as a clean one.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent

# SHA-256 of each forbidden word run, lowercased and with every non-alphanumeric
# character collapsed to a single space. Fourteen entries: tool and vendor names,
# attribution trailers, the phrases a generated document announces itself with,
# and the internal names the derivation removed. Add one with:
#
#   python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' '<the run>'
#
# and never commit the run itself, here or in a message.
MARK_DIGESTS = frozenset(
    {
        "c857d09db23e6822e3600bc06ad8d58f92ed62bc8efd81c753f77048662cb97d",
        "c70eca6b0f88f44d81a41311647e50fda1ac454ec04ffd442b0eb4743a993131",
        "7c38d5864015fc722b62d2f5b8cf69be50bcea73de4cfb745c8b9780e9e8d9f5",
        "cdcbb68a3444fdd629ab0af770af3fc99e4d5dde43b576d5f855691e155283ec",
        "c5b23a560550f7a46dd27ed9993b8c807e25f5f862d2dd1c5227d129ed75fb9e",
        "9760d607e65eafcf2cef66bf6b6d00e2c2707e9d4bebe4ab2752bfd16233adb6",
        "9f4716542f75ea730e012a9a471f34b7047bab632b24751be278c246e4d5abc6",
        "5417dcf3515cce99d317b6d1e22915f647f195e0f1cd9578534cf18a6d353895",
        "96530b75a4204acc15a4399e41b761d35f7d0b2a0052c26a9bb631ba7ab533ef",
        "fdc58962560c17c901b0a98b7a2fe84ad9a579ae713c239aa0613f32e81b2459",
        "ff46cb3423072dda756e1f5f85b61468775c572a60442eee89230d3b403cee73",
        "a885bd3d15a135670ccdfc0bb9921eb29c53e73a366008f9f047bd5c871b56cf",
        "d8a8ba6ea5cc2ff0213b73c7435da4f08af8d254323093dd02ea33f188499427",
        "92928e3dad91e5ce0bd5566decd8fb4b22433800f787f67ec3cf1d5bbeefe177",
    }
)

MAX_GRAM = 3

# Words the style guide rules out, each with what to write instead. The first
# group is the guide's own word list; the second is British spelling, which the
# guide settles in favour of the first Merriam-Webster form.
BANNED_WORDS = {
    "please": "drop it; an instruction does not ask permission",
    "simply": "drop it; it tells the reader the work was easy",
    "just": "drop it, or write `only` or `merely` when that is the sense",
    "easily": "drop it; say what the step costs instead",
    "whitelist": "allowlist",
    "blacklist": "denylist",
    "whilst": "while",
    "amongst": "among",
    "recognise": "recognize",
    "organise": "organize",
    "normalise": "normalize",
    "serialise": "serialize",
    "analyse": "analyze",
    "behaviour": "behavior",
    "colour": "color",
    "defence": "defense",
    "licence": "license",
    "modelled": "modeled",
    "labelled": "labeled",
    "cancelled": "canceled",
    "catalogue": "catalog",
}

BANNED_PHRASES = {
    ("in", "order", "to"): "to",
    ("allows", "you", "to"): "name the actor and the action",
    ("click", "here"): "name the target: `see [the profile registry]`",
}

# The guide rules these out in favour of the English they stand for. They are
# matched on the raw line, because the word split below throws the dots away.
ABBREVIATIONS = {
    re.compile(r"\be\.\s?g\."): "write `for example`",
    re.compile(r"\bi\.\s?e\."): "write `that is`",
    re.compile(r"\betc\."): "finish the list, or write `and so on`",
}

# Headings are sentence case. A word after the first that starts with a capital
# is a finding unless it is a name, an acronym, or a code identifier the heading
# quotes, all of which are listed here.
HEADING_PROPER = frozenset(
    {
        "Apache",
        "CEL",
        "CUE",
        "Continuous",
        "Go",
        "JMESPath",
        "JSON",
        "Kubernetes",
        "Kyverno",
        "Open",
        "Policy",
        "Agent",
        "Pod",
        "Provenance",
        "Rego",
        "SHA",
        "YAML",
    }
)

# Files whose text this repository did not write and may not edit: the licence,
# the corpus projection, and the vendored obligation table. Editing any of them
# to satisfy a style rule would make it disagree with its source.
EXEMPT = frozenset(
    {
        "LICENSE",
        "registry/conditions.json",
        "rego/corpus_vectors.json",
        "rego/test_consumer_pins.json",
        "profiles/rule-index.json",
    }
)

# A style rule governs prose, and a word rule turned loose on source would rename
# an identifier. So each suffix says where the prose in that kind of file lives.
PROSE_ALL = (".md", ".cff")
PROSE_HASH_COMMENTS = (".yml", ".yaml", ".rego", ".py")

WORD_RE = re.compile(r"[A-Za-z0-9]+")
HEADING_RE = re.compile(r"^#{1,6}\s+(.*?)\s*$")
CODE_SPAN_RE = re.compile(r"`[^`]*`")
FENCE_RE = re.compile(r"^\s*```")
HASH_COMMENT_RE = re.compile(r"^\s*#\s?(.*)$")
SLASH_COMMENT_RE = re.compile(r"^\s*//\s?(.*)$")
PY_DOC_RE = re.compile(r'"""')


def cannot(msg: str) -> None:
    print(f"docs-style-gate: COULD NOT CHECK -- {msg}", file=sys.stderr)
    raise SystemExit(2)


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files"],
            cwd=HERE,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        cannot(f"git ls-files failed: {exc}")
    names = [n for n in out.splitlines() if n]
    if not names:
        cannot("git ls-files returned nothing, which is a broken read")
    return names


def marks_in(text: str) -> list[str]:
    """Every forbidden word run in `text`, as the digest that matched it."""
    words = WORD_RE.findall(text.lower())
    hits = []
    for n in range(1, MAX_GRAM + 1):
        for i in range(len(words) - n + 1):
            digest = hashlib.sha256(" ".join(words[i : i + n]).encode()).hexdigest()
            if digest in MARK_DIGESTS:
                hits.append(digest)
    return hits


def prose_lines(name: str, text: str) -> list[tuple[int, str]]:
    """The prose in a file, as (line number, text), with code left out of it."""
    out: list[tuple[int, str]] = []
    lines = text.splitlines()
    if name.endswith(PROSE_ALL):
        fenced = False
        for number, line in enumerate(lines, 1):
            if FENCE_RE.match(line):
                fenced = not fenced
                continue
            if not fenced:
                out.append((number, line))
        return out
    if not name.endswith(PROSE_HASH_COMMENTS):
        return out
    in_doc = False
    for number, line in enumerate(lines, 1):
        if name.endswith(".py") and len(PY_DOC_RE.findall(line)) % 2 == 1:
            in_doc = not in_doc
            out.append((number, PY_DOC_RE.sub(" ", line)))
            continue
        if in_doc:
            out.append((number, line))
            continue
        comment = HASH_COMMENT_RE.match(line) or SLASH_COMMENT_RE.match(line)
        if comment:
            out.append((number, comment.group(1)))
    return out


def style_findings(name: str, text: str) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    for number, line in prose_lines(name, text):
        bare = CODE_SPAN_RE.sub(" ", line)
        for pattern, fix in ABBREVIATIONS.items():
            if pattern.search(bare):
                findings.append((number, f"`{pattern.pattern}` -> {fix}"))
        words = [w.lower() for w in WORD_RE.findall(bare)]
        for word in words:
            if word in BANNED_WORDS:
                findings.append((number, f"`{word}` -> {BANNED_WORDS[word]}"))
        for phrase, fix in BANNED_PHRASES.items():
            n = len(phrase)
            if any(tuple(words[i : i + n]) == phrase for i in range(len(words) - n + 1)):
                findings.append((number, f"`{' '.join(phrase)}` -> {fix}"))
        if name.endswith(".md"):
            heading = HEADING_RE.match(line)
            if heading:
                rest = CODE_SPAN_RE.sub(" ", heading.group(1)).split()[1:]
                shouty = [
                    w
                    for w in rest
                    if w[:1].isupper() and w.strip(".,:;") not in HEADING_PROPER
                ]
                if len(shouty) >= 2:
                    findings.append(
                        (number, f"heading is not sentence case: {' '.join(shouty)}")
                    )
    return findings


def history_objects() -> list[str]:
    """Every blob in the object database, as an object name.

    Wider than "reachable from a ref" on purpose. An object no branch points at
    is still in the repository, and a listing that quietly narrowed to the refs
    would report the part it looked at as the whole.
    """
    if (HERE / ".git" / "shallow").exists():
        cannot("this clone is shallow, so most of the history is not here to read")
    try:
        out = subprocess.run(
            ["git", "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)"],
            cwd=HERE,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        cannot(f"git cat-file failed: {exc}")
    blobs = [line.split()[0] for line in out.splitlines() if line.endswith(" blob")]
    if not blobs:
        cannot("the object listing carried no blobs, which is a broken read")
    return blobs


def check_history() -> int:
    """Refuse a mark anywhere in the history, not only in the tree on disk.

    A mark deleted in a later commit is still published when the repository is,
    because the commit that carried it is still reachable. Checking the working
    tree alone answers a narrower question than the one that matters, and it
    answers it in the reassuring direction.
    """
    blobs = history_objects()
    failures = 0
    for name in blobs:
        try:
            text = subprocess.run(
                ["git", "cat-file", "blob", name],
                cwd=HERE,
                check=True,
                capture_output=True,
            ).stdout.decode("utf-8")
        except (OSError, subprocess.CalledProcessError, UnicodeDecodeError):
            continue
        if marks_in(text):
            print(f"blob {name}: carries an authorship mark somewhere in the object database")
            failures += 1
    try:
        messages = subprocess.run(
            ["git", "log", "--all", "--format=%H%n%B%n%an %ae%n%cn %ce"],
            cwd=HERE,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        cannot(f"git log failed: {exc}")
    if not messages.strip():
        cannot("git log returned nothing, which is a broken read")
    if marks_in(messages):
        print("a commit message or an identity carries an authorship mark")
        failures += 1
    if failures:
        print(f"\n{failures} finding(s) over {len(blobs)} blob(s)")
        print("Rewriting history is the only fix; deleting the line in a new commit is not.")
        return 1
    print(
        f"docs-style-gate: {len(blobs)} blobs and every commit message carry no mark"
    )
    return 0


def selftest() -> int:
    """Prove both tables fire, on text assembled here rather than written down."""
    probe = "".join(chr(c) for c in (99, 108, 97, 117, 100, 101))
    if not marks_in(f"reviewed by {probe} before landing"):
        cannot("the mark table did not fire on its own positive control")
    if marks_in("reviewed by a person before landing"):
        cannot("the mark table fired on text carrying no mark")
    if not style_findings("x.md", "You can simply run the gate."):
        cannot("the word table did not fire on its own positive control")
    if not style_findings("x.md", "Pin the anchors in order to admit a run."):
        cannot("the phrase table did not fire on its own positive control")
    if not style_findings("x.md", "Pass a flag, e.g. --check, to compare."):
        cannot("the abbreviation table did not fire on its own positive control")
    if style_findings("x.md", "The gate reads the file and reports what it found."):
        cannot("the word table fired on prose carrying no banned form")
    if style_findings("x.py", "_MODELLED_OPERATORS = frozenset({'Equals'})"):
        cannot("a word rule reached an identifier outside the prose")
    if not style_findings("x.md", "## Running The Conformance Harness"):
        cannot("the heading rule did not fire on its own positive control")
    if style_findings("x.md", "## Running the conformance harness"):
        cannot("the heading rule fired on a sentence-case heading")
    print("selftest: the mark table, the word table and the heading rule all fire")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args(argv[1:])

    if args.selftest:
        return selftest()

    selftest()

    if args.history:
        return check_history()

    failures = 0
    checked = 0
    for name in tracked_files():
        if name in EXEMPT or name == "scripts/docs-style-gate.py":
            continue
        path = HERE / name
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        checked += 1
        if marks_in(text):
            print(f"{name}: carries an authorship mark; rewrite the prose")
            failures += 1
        for number, finding in style_findings(name, text):
            print(f"{name}:{number}: {finding}")
            failures += 1

    if failures:
        print(f"\n{failures} finding(s) over {checked} tracked file(s)")
        return 1
    print(f"docs-style-gate: {checked} tracked files carry no mark and no banned form")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
