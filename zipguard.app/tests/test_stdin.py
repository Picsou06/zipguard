from __future__ import annotations

import io
import json
import sys
import tempfile
from pathlib import Path

import pytest

from conftest import write_tar, write_zip
from zipguard.__main__ import EXIT_ERROR, EXIT_OK, EXIT_UNSAFE, main


def _feed(monkeypatch, data: bytes) -> None:
	monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))


@pytest.fixture
def no_disk(monkeypatch):
	def forbidden(*args, **kwargs):
		raise AssertionError("La lecture de l'entrée standard a tenté d'écrire sur le disque.")

	monkeypatch.setattr(tempfile, "mkdtemp", forbidden)


def test_an_archive_on_stdin_is_scanned(tmp_path: Path, monkeypatch, capsys, no_disk) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	_feed(monkeypatch, archive.read_bytes())
	assert main(["scan", "-", "--json"]) == EXIT_OK
	payload = json.loads(capsys.readouterr().out)
	assert payload["archive"] == "-"
	assert payload["stats"]["kind"] == "zip"


def test_a_bomb_on_stdin_is_refused(tmp_path: Path, monkeypatch, no_disk) -> None:
	archive = write_tar(tmp_path / "bombe.tar.gz", {"a.txt": b"A" * 2_000_000})
	_feed(monkeypatch, archive.read_bytes())
	assert main(["scan", "-", "--no-color"]) == EXIT_UNSAFE


def test_a_nested_bomb_on_stdin_is_inspected_in_memory(
	tmp_path: Path, monkeypatch, capsys, no_disk
) -> None:
	inner = write_zip(tmp_path / "interne.zip", {"a.txt": b"A" * 2_000_000})
	outer = write_zip(tmp_path / "externe.zip", {"notes.txt": inner.read_bytes()})
	_feed(monkeypatch, outer.read_bytes())
	assert main(["scan", "-", "--json"]) == EXIT_UNSAFE
	assert json.loads(capsys.readouterr().out)["codes"] == ["nested"]


def test_stdin_beyond_the_cap_is_cut(monkeypatch, capsys) -> None:
	_feed(monkeypatch, b"x" * 2_500_000)
	assert main(["scan", "-", "--json", "--max-download-mb", "1"]) == EXIT_UNSAFE
	payload = json.loads(capsys.readouterr().out)
	assert payload["codes"] == ["download_cap"]
	assert payload["stats"]["downloaded_bytes"] <= 1_000_000 + 65536


def test_stdin_can_be_read_only_once(monkeypatch) -> None:
	_feed(monkeypatch, b"")
	assert main(["scan", "-", "-"]) == EXIT_ERROR


def test_stdin_mixes_with_files(tmp_path: Path, monkeypatch, capsys) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	_feed(monkeypatch, archive.read_bytes())
	assert main(["scan", "-", str(archive), "--json"]) == EXIT_OK
	assert [item["archive"] for item in json.loads(capsys.readouterr().out)] == ["-", str(archive)]
