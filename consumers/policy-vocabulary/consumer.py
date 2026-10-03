"""Install selected reader code and enforce a receiving project's publication gate."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
import zipfile

HERE = Path(__file__).resolve().parent
SELECTION = HERE / "host-selection.json"
PACKAGE = "probity_policy_vocabulary_reader"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def selection() -> dict:
    selected = json.loads(SELECTION.read_bytes())
    if selected["qualityPolicy"] != {"minimumCorrectPerRow": 16,
                                      "minimumFullyCorrectPairsPerRow": 8, "rows": 8}:
        raise ValueError("this placement requires all sixteen answers and all eight pairs per row")
    return selected


def save(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def environment() -> dict:
    return {k: v for k, v in os.environ.items()
            if not k.startswith(("PYTHON", "GIT_"))}


def git(checkout: Path, *arguments: str) -> bytes:
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(checkout), *arguments],
        env=environment(), timeout=30)


def reviewed(checkout: Path, pin: dict, commit: str) -> bytes:
    raw = git(checkout, "show", f"{commit}:{pin['path']}")
    if sha(raw) != pin["sha256"]:
        raise ValueError("reviewed source differs from host selection")
    return raw


def install(checkout: Path, output: Path) -> dict:
    """Use committed selected code, never code supplied in the evidence packet."""
    selected = selection()
    checkout = checkout.resolve()
    if git(checkout, "rev-parse", "--show-toplevel").decode().strip() != str(checkout):
        raise ValueError("Observer checkout must be a repository root")
    if git(checkout, "rev-parse", "HEAD").decode().strip() != selected["observerCommit"]:
        raise ValueError("Observer checkout differs from the selected commit")
    if output.exists():
        raise ValueError("installation output exists; replace through a fresh installation")
    contract = reviewed(checkout, selected["sourceContract"], selected["observerCommit"])
    if json.loads(contract)["files"] != selected["sourceContract"]["files"]:
        raise ValueError("source contract differs from independently selected file pins")
    builder_raw = reviewed(checkout, selected["builder"], selected["observerCommit"])
    for pin in selected["sourceContract"]["files"].values():
        reviewed(checkout, pin, pin["commit"])
    output.mkdir(parents=True)
    save(output / "host-selection.json", selected)
    contract_file = output / "source-contract.json"
    contract_file.write_bytes(contract)
    builder_file = output / "selected-builder.py"
    builder_file.write_bytes(builder_raw)
    with (output / "installation.log").open("wb") as log:
        # The selected builder checks each workspace source against its digest
        # and full reviewed Git commit, then checks every wheel member.
        subprocess.run([sys.executable, "-I", "-B", str(builder_file), str(checkout),
                        str(output / "wheel"), "--contract", str(contract_file),
                        "--contract-sha256", selected["sourceContract"]["sha256"]],
                       check=True, env=environment(), stdout=log, stderr=subprocess.STDOUT,
                       timeout=90)
        build = json.loads((output / "wheel/build-record.json").read_bytes())
        subprocess.run([sys.executable, "-I", "-m", "venv", str(output / "env")],
                       check=True, env=environment(), stdout=log, stderr=subprocess.STDOUT,
                       timeout=60)
        wheel = output / "wheel" / build["wheel"]["name"]
        subprocess.run([str(output / "env/bin/python"), "-I", "-m", "pip", "install",
                        "--no-index", "--no-deps", "--no-compile", str(wheel.resolve())],
                       check=True, env=environment(), stdout=log, stderr=subprocess.STDOUT,
                       timeout=60)
    receipt = {"schema": "policy-vocabulary-host-install-v1",
               "selectionSha256": sha(SELECTION.read_bytes()), "build": build,
               "modelRuntimeInstalled": False,
               "replacement": "Create a fresh selected environment, replay retained evidence, then select that environment."}
    save(output / "installation.json", receipt)
    verify_installation(output)
    return receipt


def verify_installation(output: Path) -> Path:
    """Validate installed reader bytes before allowing Python to load them."""
    selected = selection()
    receipt = json.loads((output / "installation.json").read_bytes())
    if receipt["selectionSha256"] != sha(SELECTION.read_bytes()):
        raise ValueError("installation was built under a different host selection")
    if receipt["build"]["sourceContractSha256"] != selected["sourceContract"]["sha256"]:
        raise ValueError("installed reader has a different source contract")
    sites = list((output / "env/lib").glob("python*/site-packages"))
    if len(sites) != 1 or sites[0].is_symlink():
        raise ValueError("installation does not contain one private site directory")
    site = sites[0]
    for path in site.iterdir():
        if path.suffix == ".pth" or path.name in {"sitecustomize.py", "usercustomize.py"}:
            raise ValueError("installation contains an automatic Python startup hook")
        if path.name.startswith(("llama_cpp", "torch", "transformers")):
            raise ValueError("model runtime is outside this reader installation")
    expected = {name for name in selected["sourceContract"]["files"]
                if name.startswith(PACKAGE + "/")}
    package = site / PACKAGE
    if not package.is_dir() or package.is_symlink():
        raise ValueError("installed reader namespace is not a regular directory")
    entries = list(package.rglob("*"))
    for path in entries:
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("installed reader contains an unselected or nonregular entry")
    actual = {str(path.relative_to(site)) for path in entries}
    if actual != expected:
        raise ValueError("installed reader file population differs from selected sources")
    for name in expected:
        path = site / name
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError("installed reader source contains a symlink")
        if sha(path.read_bytes()) != selected["sourceContract"]["files"][name]["sha256"]:
            raise ValueError("installed reader differs from reviewed source")
    return site


def download(output: Path) -> None:
    """Download in the standalone Linux CLI, with no other active alarm timer."""
    selected = selection()["archive"]
    if output.exists():
        raise ValueError("download output already exists")
    if urlsplit(selected["url"]).scheme != "https":
        raise ValueError("selected archive URL must use HTTPS")
    if signal.getitimer(signal.ITIMER_REAL)[0]:
        raise ValueError("download needs a standalone CLI without an active alarm timer")
    started = time.monotonic()
    created = False
    previous = signal.getsignal(signal.SIGALRM)
    def deadline(_signum: int, _frame: object) -> None:
        raise TimeoutError("selected archive download exceeded 90 seconds")
    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, 90)
    try:
        with urllib.request.urlopen(selected["url"], timeout=15) as response:
            if urlsplit(response.geturl()).scheme != "https":
                raise ValueError("final archive URL must use HTTPS")
            with output.open("xb") as stream:
                created = True
                remaining = selected["bytes"]
                while remaining:
                    if time.monotonic() - started >= 90:
                        raise TimeoutError("selected archive download exceeded 90 seconds")
                    chunk = response.read(min(65536, remaining))
                    if not chunk:
                        raise ValueError("selected archive response ended early")
                    stream.write(chunk)
                    remaining -= len(chunk)
                if response.read(1):
                    raise ValueError("selected archive response exceeds declared bytes")
        authenticate_archive(output)
    except BaseException:
        if created:
            output.unlink(missing_ok=True)
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def authenticate_archive(archive: Path) -> bytes:
    expected = selection()["archive"]
    if not stat.S_ISREG(archive.lstat().st_mode):
        raise ValueError("archive is not a regular file")
    with archive.open("rb") as stream:
        raw = stream.read(expected["bytes"] + 1)
    if len(raw) != expected["bytes"] or sha(raw) != expected["sha256"]:
        raise ValueError("archive bytes differ from the receiving project's selection")
    return raw


def unpack(archive: Path, target: Path) -> None:
    raw = authenticate_archive(archive)
    expected = selection()["archive"]
    with zipfile.ZipFile(io.BytesIO(raw)) as source:
        members = source.infolist()
        names = [item.filename for item in members]
        if (len(members) != expected["memberCount"] or len(set(names)) != len(names)
                or sum(item.file_size for item in members) != expected["expandedBytes"]):
            raise ValueError("archive member population differs from host selection")
        for item in members:
            path = PurePosixPath(item.filename)
            mode = item.external_attr >> 16
            if (path.is_absolute() or str(path) != item.filename
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or "\\" in item.filename or item.is_dir()
                    or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not stat.S_ISREG(mode))):
                raise ValueError("archive contains an unsafe or nonregular member")
            destination = target.joinpath(*path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read(item))


def replay(installation: Path, packet: Path, output: Path) -> dict:
    site = verify_installation(installation)
    selected = selection()
    pins_file = output / "host-pins.json"
    save(pins_file, selected["packetPins"])
    # Execute only a fresh copy of validated source bytes. The original site
    # directory can contain pip and never enters the reader's import search.
    # -I -S disables environment, user site, .pth and startup imports. -B only
    # prevents new cache writes; it does not authenticate existing bytecode.
    entry = "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module('" + PACKAGE + ".cli',run_name='__main__')"
    calls = []
    started = time.monotonic_ns()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="host-selected-reader-") as temporary:
        stage = Path(temporary)
        for name in selected["sourceContract"]["files"]:
            if not name.startswith(PACKAGE + "/"):
                continue
            raw = (site / name).read_bytes()
            if sha(raw) != selected["sourceContract"]["files"][name]["sha256"]:
                raise ValueError("installed reader changed before isolated source copy")
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        command = [str(installation / "env/bin/python"), "-I", "-S", "-B", "-c", entry,
                   str(stage), str(packet), "--pins-file", str(pins_file),
                   "--minimum-correct-per-row", "16", "--minimum-pairs-per-row", "8"]
        for number in (1, 2):
            call = subprocess.run(command, cwd=output, env=environment(),
                                  capture_output=True, timeout=30)
            (output / f"reader-{number}.json").write_bytes(call.stdout)
            (output / f"reader-{number}.stderr").write_bytes(call.stderr)
            if call.returncode not in {0, 1}:
                raise ValueError("installed reader failed to produce a gate decision")
            calls.append((call.returncode, json.loads(call.stdout)))
    if calls[0] != calls[1]:
        raise ValueError("installed reader decision changed on repeated selected bytes")
    result = calls[0][1]
    admitted = result.get("consumerDecision") == "admit-scoped-quality"
    if calls[0][0] != (0 if admitted else 1):
        raise ValueError("installed reader exit status disagrees with admission decision")
    evidence = result.get("evidenceDecision") == "accept-scoped-evidence"
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    record = {"schema": "policy-vocabulary-host-gate-v1",
              "publicationDecision": "publish-scoped-report" if evidence else "hold-evidence",
              "modelQualityDecision": "admit-scoped-quality" if evidence and admitted else
                                      "hold-quality" if evidence else "hold-evidence",
              "effectDecision": "hold-no-effect-authorization",
              "qualityPolicy": selected["qualityPolicy"], "reader": result,
              "repeatStructuredDecisionExact": True,
              "readerWallNanoseconds": time.monotonic_ns() - started,
              "readerChildrenCPUSeconds": (after.ru_utime + after.ru_stime
                                            - before.ru_utime - before.ru_stime),
              "readerChildrenLifetimePeakRSSKiB": after.ru_maxrss,
              "resourceScope": "Two installed-reader subprocesses; lifetime child peak RSS on Linux, distinct from original model-run resources.",
              "consumerModelCalls": 0, "consumerEffects": 0,
              "selectionSha256": sha(SELECTION.read_bytes()), "scope": selected["scope"]}
    save(output / "decision.json", record)
    return record


def evaluate(installation: Path, archive: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    try:
        with tempfile.TemporaryDirectory(prefix="host-vocabulary-packet-") as temporary:
            packet = Path(temporary)
            unpack(archive, packet)
            return replay(installation.resolve(), packet, output.resolve())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        record = {"schema": "policy-vocabulary-host-gate-v1",
                  "publicationDecision": "hold-evidence", "modelQualityDecision": "hold-evidence",
                  "effectDecision": "hold-no-effect-authorization",
                  "error": {"type": type(exc).__name__, "message": str(exc)}}
        save(output / "decision.json", record)
        return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("install")
    setup.add_argument("checkout", type=Path)
    setup.add_argument("output", type=Path)
    fetch = sub.add_parser("download")
    fetch.add_argument("output", type=Path)
    gate = sub.add_parser("evaluate")
    gate.add_argument("installation", type=Path)
    gate.add_argument("archive", type=Path)
    gate.add_argument("output", type=Path)
    gate.add_argument("--purpose", choices=("publication", "model-quality"), required=True)
    args = parser.parse_args()
    if args.command == "install":
        record = install(args.checkout, args.output.resolve())
    elif args.command == "download":
        download(args.output)
        return 0
    else:
        record = evaluate(args.installation, args.archive, args.output)
        print(json.dumps(record, indent=2, allow_nan=False))
        key, accept = (("publicationDecision", "publish-scoped-report") if args.purpose == "publication"
                       else ("modelQualityDecision", "admit-scoped-quality"))
        return 0 if record[key] == accept else 1
    print(json.dumps(record, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
