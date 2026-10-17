from __future__ import annotations

import zipfile
from pathlib import Path

from conftest import write_tar, write_zip

from zipguard import Limits, Scanner


def _nested_bomb(tmp_path: Path) -> Path:
	"""
	Description: Construit une archive dont le danger n'apparaît qu'une fois ouverte l'archive interne.
	Usage: outer = _nested_bomb(tmp_path).
	Inputs: tmp_path (Path) dossier de travail du test.
	Outputs: Path de l'archive externe, inoffensive en surface.
	"""

	inner = write_zip(tmp_path / "interne.zip", {"gros.txt": b"A" * 5_000_000})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(inner, "interne.zip")
	return outer


def test_outer_archive_looks_harmless_on_its_own(tmp_path: Path) -> None:
	outer = _nested_bomb(tmp_path)
	with zipfile.ZipFile(outer) as archive:
		info = archive.infolist()[0]
		assert info.file_size / info.compress_size < 2


def test_recursion_finds_the_bomb_hidden_one_level_down(tmp_path: Path) -> None:
	outer = _nested_bomb(tmp_path)
	verdict = Scanner(Limits(max_ratio=5.0, max_depth=2)).inspect(outer)
	assert verdict.safe is False
	assert any("interne.zip" in reason for reason in verdict.reasons)


def test_recursion_exposes_the_child_verdict(tmp_path: Path) -> None:
	outer = _nested_bomb(tmp_path)
	verdict = Scanner(Limits(max_ratio=5.0, max_depth=2)).inspect(outer)
	assert len(verdict.children) == 1
	assert verdict.children[0].stats["name"] == "interne.zip"
	assert verdict.children[0].safe is False


def test_uninspectable_nesting_is_refused_rather_than_trusted(tmp_path: Path) -> None:
	outer = _nested_bomb(tmp_path)
	verdict = Scanner(Limits(max_ratio=5.0, max_depth=0)).inspect(outer)
	assert verdict.safe is False
	assert any("profondeur" in reason.lower() for reason in verdict.reasons)


def test_benign_nesting_stays_safe(tmp_path: Path) -> None:
	inner = write_zip(tmp_path / "interne.zip", {"note.txt": b"bonjour"})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w") as archive:
		archive.write(inner, "interne.zip")
	verdict = Scanner(Limits(max_depth=2)).inspect(outer)
	assert verdict.safe is True
	assert verdict.children[0].safe is True


def test_nested_archive_renamed_is_still_inspected(tmp_path: Path) -> None:
	inner = write_zip(tmp_path / "interne.zip", {"gros.txt": b"A" * 5_000_000})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(inner, "notes.txt")
	verdict = Scanner(Limits(max_ratio=5.0, max_depth=2)).inspect(outer)
	assert verdict.safe is False
	assert any("notes.txt" in reason for reason in verdict.reasons)


def test_depth_is_reported_in_stats(tmp_path: Path) -> None:
	outer = _nested_bomb(tmp_path)
	verdict = Scanner(Limits(max_ratio=5.0, max_depth=2)).inspect(outer)
	assert verdict.stats["depth"] == 0
	assert verdict.children[0].stats["depth"] == 1


def test_tar_inside_zip_is_inspected(tmp_path: Path) -> None:
	inner = write_tar(tmp_path / "interne.tar.gz", {"gros.txt": b"A" * 5_000_000})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(inner, "interne.tar.gz")
	verdict = Scanner(Limits(max_ratio=5.0, max_depth=2)).inspect(outer)
	assert verdict.safe is False
	assert verdict.children[0].stats["kind"] == "tar.gz"


def test_nested_scan_budget_is_bounded(tmp_path: Path) -> None:
	inner = write_zip(tmp_path / "petite.zip", {"note.txt": b"bonjour"})
	outer = tmp_path / "beaucoup.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		for index in range(5):
			archive.write(inner, f"interne{index}.zip")

	verdict = Scanner(Limits(max_depth=2, max_nested_scans=2)).inspect(outer)
	assert len(verdict.children) == 2
	assert verdict.safe is False
	assert any("budget" in reason.lower() for reason in verdict.reasons)


def test_nested_stats_count_the_candidates(tmp_path: Path) -> None:
	inner = write_zip(tmp_path / "petite.zip", {"note.txt": b"bonjour"})
	outer = tmp_path / "deux.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(inner, "a.zip")
		archive.write(inner, "b.zip")
	verdict = Scanner(Limits(max_depth=2)).inspect(outer)
	assert verdict.stats["nested_archives"] == 2
