"""Interface de linha de comando: show, verify, list, compare, replay."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

from .config import TraceSeedConfig
from .errors import IntegrityError, InvalidPackageError, ReplayError
from .replay import ReplayRunner
from .serialization import SafeSerializer
from .storage import ArchiveStorage

_VERSION = "0.1.0"


def _make_storage() -> ArchiveStorage:
    config = TraceSeedConfig()
    return ArchiveStorage(config, SafeSerializer(config))


def _load_summary(storage: ArchiveStorage, path: str) -> dict[str, Any]:
    files = storage.load_files(path)
    if "summary.json" not in files:
        raise InvalidPackageError("summary.json ausente")
    return cast(dict[str, Any], json.loads(files["summary.json"].decode("utf-8")))


def _cmd_show(args: argparse.Namespace) -> int:
    storage = _make_storage()
    try:
        summary = _load_summary(storage, args.path)
    except (InvalidPackageError, IntegrityError) as exc:
        print(f"traceseed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    exc_info = summary.get("exception", {})
    print(f"Incident:     {summary.get('incident_id', '?')}")
    print(f"Fingerprint:  {summary.get('fingerprint', '?')}")
    print(f"Operation:    {summary.get('operation') or '(none)'}")
    print(f"Created:      {summary.get('created_at', '?')}")
    print(f"Exception:    {exc_info.get('type_name', '?')}: {exc_info.get('message', '?')}")
    top = summary.get("top_frame")
    if top:
        print(
            f"Top frame:    {top.get('filename')}:{top.get('line_number')} in {top.get('function')}"
        )
    collector_errors = summary.get("collector_errors", [])
    if collector_errors:
        print(f"Collector errors: {len(collector_errors)}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    storage = _make_storage()
    try:
        manifest = storage.verify(args.path)
    except IntegrityError as exc:
        print(f"traceseed: integridade: {exc}", file=sys.stderr)
        return 1
    except (InvalidPackageError, OSError) as exc:
        print(f"traceseed: {exc}", file=sys.stderr)
        return 1

    print(f"OK: {Path(args.path).name} ({manifest.get('incident_id', '?')})")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    packages = sorted(directory.glob("*.tseed"))
    if not packages:
        print(f"No .tseed packages found in {directory}")
        return 0
    for pkg in packages:
        print(pkg.name)
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    storage = _make_storage()
    try:
        first = _load_summary(storage, args.path1)
        second = _load_summary(storage, args.path2)
    except (InvalidPackageError, IntegrityError) as exc:
        print(f"traceseed: {exc}", file=sys.stderr)
        return 1

    fp1 = first.get("fingerprint")
    fp2 = second.get("fingerprint")
    same = fp1 == fp2
    print(f"Same fingerprint: {'yes' if same else 'no'}")
    print(f"  {Path(args.path1).name}: {fp1}")
    print(f"  {Path(args.path2).name}: {fp2}")
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    if not args.allow:
        print(
            "traceseed: replay executes application code. Use --allow to confirm.",
            file=sys.stderr,
        )
        return 2

    runner = ReplayRunner()
    try:
        result = runner.run(args.path, allow_code_execution=True)
        print(f"Replay result: {result!r}")
        return 0
    except ReplayError as exc:
        print(f"traceseed: replay: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"traceseed: replay exception: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="traceseed",
        description="TraceSeed diagnostic package tool",
    )
    parser.add_argument("--version", action="version", version=f"traceseed {_VERSION}")

    sub = parser.add_subparsers(dest="command")

    p_show = sub.add_parser("show", help="Show package contents")
    p_show.add_argument("path")
    p_show.add_argument("--json", action="store_true")

    p_verify = sub.add_parser("verify", help="Verify package integrity")
    p_verify.add_argument("path")

    p_list = sub.add_parser("list", help="List .tseed packages in a directory")
    p_list.add_argument("directory")

    p_compare = sub.add_parser("compare", help="Compare two packages")
    p_compare.add_argument("path1")
    p_compare.add_argument("path2")

    p_replay = sub.add_parser("replay", help="Replay a captured call")
    p_replay.add_argument("path")
    p_replay.add_argument("--allow", action="store_true", help="Allow code execution")

    args = parser.parse_args(argv)

    if args.command == "show":
        return _cmd_show(args)
    if args.command == "verify":
        return _cmd_verify(args)
    if args.command == "list":
        return _cmd_list(args)
    if args.command == "compare":
        return _cmd_compare(args)
    if args.command == "replay":
        return _cmd_replay(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
