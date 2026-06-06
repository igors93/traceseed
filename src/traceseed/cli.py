"""Command-line interface for inspecting TraceSeed packages."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

from .config import TraceSeedConfig
from .errors import IntegrityError, InvalidPackageError, ReplayError, TraceSeedError
from .replay import ReplayRunner
from .serialization import SafeSerializer
from .storage import ArchiveStorage

_VERSION = "0.1.0"


def _make_storage() -> ArchiveStorage:
    config = TraceSeedConfig()
    return ArchiveStorage(config, SafeSerializer(config))


def _load_summary(storage: ArchiveStorage, path: str) -> dict[str, Any]:
    files = storage.load_files(path)
    storage.verify_files(files)
    if "summary.json" not in files:
        raise InvalidPackageError("summary.json is missing")
    try:
        value = json.loads(files["summary.json"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InvalidPackageError("summary.json is invalid") from error
    if not isinstance(value, dict):
        raise InvalidPackageError("summary.json must contain a JSON object")
    exception = value.get("exception")
    if exception is not None and not isinstance(exception, dict):
        raise InvalidPackageError("summary exception must be a JSON object")
    return cast(dict[str, Any], value)


def _cmd_show(args: argparse.Namespace) -> int:
    try:
        summary = _load_summary(_make_storage(), args.path)
    except (TraceSeedError, OSError) as error:
        print(f"traceseed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    exception = summary.get("exception") or {}
    print(f"Incident:     {summary.get('incident_id', '?')}")
    print(f"Fingerprint:  {summary.get('fingerprint', '?')}")
    print(f"Operation:    {summary.get('operation') or '(none)'}")
    print(f"Created:      {summary.get('created_at', '?')}")
    print(f"Exception:    {exception.get('type_name', '?')}: {exception.get('message', '?')}")
    top_frame = summary.get("top_frame")
    if isinstance(top_frame, dict):
        print(
            "Top frame:    "
            f"{top_frame.get('filename')}:{top_frame.get('line_number')} "
            f"in {top_frame.get('function')}"
        )
    collector_errors = summary.get("collector_errors")
    if isinstance(collector_errors, list) and collector_errors:
        print(f"Collector errors: {len(collector_errors)}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        manifest = _make_storage().verify(args.path)
    except IntegrityError as error:
        print(f"traceseed: integrity: {error}", file=sys.stderr)
        return 1
    except (InvalidPackageError, OSError) as error:
        print(f"traceseed: {error}", file=sys.stderr)
        return 1
    print(f"OK: {Path(args.path).name} ({manifest.get('incident_id', '?')})")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    try:
        packages = sorted(directory.glob("*.tseed"))
    except OSError as error:
        print(f"traceseed: {error}", file=sys.stderr)
        return 1
    if not packages:
        print(f"No .tseed packages found in {directory}")
        return 0
    for package in packages:
        print(package.name)
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    storage = _make_storage()
    try:
        first = _load_summary(storage, args.path1)
        second = _load_summary(storage, args.path2)
    except (TraceSeedError, OSError) as error:
        print(f"traceseed: {error}", file=sys.stderr)
        return 1
    first_fingerprint = first.get("fingerprint")
    second_fingerprint = second.get("fingerprint")
    same = first_fingerprint == second_fingerprint
    print(f"Same fingerprint: {'yes' if same else 'no'}")
    print(f"  {Path(args.path1).name}: {first_fingerprint}")
    print(f"  {Path(args.path2).name}: {second_fingerprint}")
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    if not args.allow_code_execution:
        print(
            "traceseed: replay executes application code. Use --allow-code-execution to confirm.",
            file=sys.stderr,
        )
        return 2
    try:
        result = ReplayRunner().run(args.path, allow_code_execution=True)
    except ReplayError as error:
        print(f"traceseed: replay: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        print(
            f"traceseed: replay exception: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1
    print(f"Replay result: {result!r}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="traceseed",
        description="TraceSeed diagnostic package tool",
    )
    parser.add_argument("--version", action="version", version=f"traceseed {_VERSION}")
    commands = parser.add_subparsers(dest="command")

    show_parser = commands.add_parser("show", help="Show package contents")
    show_parser.add_argument("path")
    show_parser.add_argument("--json", action="store_true")

    verify_parser = commands.add_parser("verify", help="Verify package integrity")
    verify_parser.add_argument("path")

    list_parser = commands.add_parser("list", help="List .tseed packages")
    list_parser.add_argument("directory")

    compare_parser = commands.add_parser("compare", help="Compare two packages")
    compare_parser.add_argument("path1")
    compare_parser.add_argument("path2")

    replay_parser = commands.add_parser("replay", help="Replay a captured call")
    replay_parser.add_argument("path")
    replay_parser.add_argument(
        "--allow-code-execution",
        "--allow",
        dest="allow_code_execution",
        action="store_true",
        help="Allow application code execution",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "show": _cmd_show,
        "verify": _cmd_verify,
        "list": _cmd_list,
        "compare": _cmd_compare,
        "replay": _cmd_replay,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 0
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
