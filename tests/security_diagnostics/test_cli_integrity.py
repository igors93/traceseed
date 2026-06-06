from __future__ import annotations

import json

from traceseed.cli import main

from ._helpers import rewrite_zip_member, write_tseed


def _summary(fingerprint: str):
    return {
        "incident_id": "diagnostic",
        "fingerprint": fingerprint,
        "operation": "operation",
        "created_at": "2026-01-01T00:00:00+00:00",
        "exception": {"type_name": "RuntimeError", "message": "failure"},
        "top_frame": None,
        "collector_errors": [],
    }


def test_show_rejects_tampered_summary_instead_of_displaying_it(tmp_path, capsys):
    package = write_tseed(
        tmp_path / "tampered-show.tseed",
        {"summary.json": json.dumps(_summary("a" * 32))},
    )
    rewrite_zip_member(package, "summary.json", json.dumps(_summary("b" * 32)))

    exit_code = main(["show", str(package)])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert "b" * 32 not in captured.out


def test_compare_rejects_tampered_package(tmp_path, capsys):
    first = write_tseed(
        tmp_path / "first.tseed",
        {"summary.json": json.dumps(_summary("a" * 32))},
    )
    second = write_tseed(
        tmp_path / "second.tseed",
        {"summary.json": json.dumps(_summary("b" * 32))},
    )
    rewrite_zip_member(second, "summary.json", json.dumps(_summary("a" * 32)))

    exit_code = main(["compare", str(first), str(second)])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert "Same fingerprint: yes" not in captured.out


def test_show_handles_invalid_summary_json_as_controlled_cli_error(tmp_path, capsys):
    package = write_tseed(tmp_path / "invalid-json.tseed", {"summary.json": "{"})

    exit_code = main(["show", str(package)])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert captured.err


def test_show_rejects_non_object_summary_json(tmp_path, capsys):
    package = write_tseed(tmp_path / "summary-list.tseed", {"summary.json": "[]"})

    exit_code = main(["show", str(package)])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert captured.err


def test_compare_handles_invalid_summary_json_as_controlled_cli_error(tmp_path, capsys):
    first = write_tseed(tmp_path / "first.tseed", {"summary.json": json.dumps(_summary("a" * 32))})
    second = write_tseed(tmp_path / "invalid.tseed", {"summary.json": "{"})

    exit_code = main(["compare", str(first), str(second)])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert captured.err


def test_show_verifies_integrity_before_json_output(tmp_path, capsys):
    package = write_tseed(
        tmp_path / "json-output.tseed",
        {"summary.json": json.dumps(_summary("a" * 32))},
    )
    rewrite_zip_member(package, "summary.json", json.dumps(_summary("c" * 32)))

    exit_code = main(["show", str(package), "--json"])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert captured.out == ""
