from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from zipguard import Limits, Scanner, detect_kind, open_archive

py7zr = pytest.importorskip("py7zr", reason="L'extra 7z n'est pas installé.")


def write_7z(path: Path, files: dict[str, bytes]) -> Path:
	"""
	Description: Fabrique une archive 7z de test à partir d'un dictionnaire de contenus.
	Usage: write_7z(tmp_path / "a.7z", {"a.txt": b"bonjour"}).
	Inputs: path (Path) destination, files (dict[str, bytes]) nom d'entrée vers contenu.
	Outputs: Path de l'archive écrite.
	"""

	import io

	with py7zr.SevenZipFile(path, "w") as archive:
		for name, data in files.items():
			archive.writef(io.BytesIO(data), name)
	return path


def test_a_seven_zip_archive_is_detected_by_signature(tmp_path: Path) -> None:
	archive = write_7z(tmp_path / "deguise.bin", {"note.txt": b"bonjour"})
	assert detect_kind(archive) == "7z"


def test_entries_are_listed_from_the_manifest(tmp_path: Path) -> None:
	archive = write_7z(tmp_path / "a.7z", {"a.txt": b"bonjour", "b.txt": b"salut"})
	with open_archive(archive) as handle:
		assert sorted(entry.name for entry in handle.entries()) == ["a.txt", "b.txt"]


def test_a_benign_seven_zip_is_safe(tmp_path: Path) -> None:
	archive = write_7z(tmp_path / "ok.7z", {"note.txt": b"bonjour le monde"})
	verdict = Scanner().inspect(archive)
	assert verdict.safe is True
	assert verdict.stats["kind"] == "7z"


def test_a_seven_zip_bomb_hits_the_same_thresholds(tmp_path: Path) -> None:
	archive = write_7z(tmp_path / "bombe.7z", {"gros.txt": b"A" * 4_000_000})
	verdict = Scanner(Limits(max_ratio=50.0)).inspect(archive)
	assert verdict.safe is False
	assert any("Ratio" in reason for reason in verdict.reasons)


def test_a_seven_zip_nested_in_a_zip_is_inspected(tmp_path: Path) -> None:
	inner = write_7z(tmp_path / "interne.7z", {"gros.txt": b"A" * 4_000_000})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(inner, "donnees.bin")

	verdict = Scanner(Limits(max_ratio=50.0, max_depth=2)).inspect(outer)
	assert verdict.safe is False
	assert verdict.children[0].stats["kind"] == "7z"


def test_a_benign_seven_zip_extracts(tmp_path: Path) -> None:
	archive = write_7z(tmp_path / "ok.7z", {"note.txt": b"salut"})
	written = Scanner().safe_extract(archive, tmp_path / "out")
	assert written == 5
	assert (tmp_path / "out" / "note.txt").read_bytes() == b"salut"


def test_a_seven_zip_symlink_yields_a_verdict_not_a_crash(tmp_path: Path) -> None:
	source = tmp_path / "src"
	source.mkdir()
	(source / "lien").symlink_to("/etc/hostname")
	archive = tmp_path / "lien.7z"
	with py7zr.SevenZipFile(archive, "w") as handle:
		handle.write(source / "lien", "lien")

	verdict = Scanner().inspect(archive)
	assert verdict.stats["links"] == 1


def test_a_seven_zip_symlink_is_never_extracted(tmp_path: Path) -> None:
	from zipguard.scanner import ExtractionRefused

	source = tmp_path / "src"
	source.mkdir()
	(source / "lien").symlink_to("/etc/hostname")
	archive = tmp_path / "lien.7z"
	with py7zr.SevenZipFile(archive, "w") as handle:
		handle.write(source / "lien", "lien")

	with pytest.raises(ExtractionRefused):
		Scanner().safe_extract(archive, tmp_path / "out")
	assert not (tmp_path / "out").exists()
