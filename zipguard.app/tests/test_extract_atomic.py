from __future__ import annotations

import io
import tarfile
import warnings
import zipfile
from pathlib import Path

import pytest

from conftest import write_zip
from zipguard import Limits, Scanner
from zipguard.scanner import ExtractionRefused, QuotaExceeded


def _overflowing_zip(path: Path) -> Path:
	"""
	Description: Fabrique une archive dont la deuxième entrée fait sauter un quota de 1000 octets.
	Usage: _overflowing_zip(tmp_path / "x.zip").
	Inputs: path (Path) destination.
	Outputs: Path de l'archive écrite.
	"""

	with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
		archive.writestr("a.txt", b"nouveau")
		archive.writestr("b.bin", bytes(range(256)) * 12)
	return path


def _write_tar_members(path: Path, members: list[tarfile.TarInfo], data: dict[str, bytes]) -> Path:
	with tarfile.open(path, "w") as archive:
		for info in members:
			payload = data.get(info.name)
			if payload is not None:
				info.size = len(payload)
				archive.addfile(info, io.BytesIO(payload))
			else:
				archive.addfile(info)
	return path


def _symlink(name: str, target: str) -> tarfile.TarInfo:
	info = tarfile.TarInfo(name)
	info.type = tarfile.SYMTYPE
	info.linkname = target
	return info


def test_a_failed_extraction_leaves_existing_files_untouched(tmp_path: Path) -> None:
	destination = tmp_path / "out"
	destination.mkdir()
	(destination / "a.txt").write_text("PRECIEUX")
	archive = _overflowing_zip(tmp_path / "x.zip")

	with pytest.raises(QuotaExceeded):
		Scanner(Limits(max_extract_bytes=1000)).safe_extract(archive, destination)

	assert (destination / "a.txt").read_text() == "PRECIEUX"
	assert sorted(p.name for p in destination.iterdir()) == ["a.txt"]


def test_a_failed_extraction_removes_the_destination_it_created(tmp_path: Path) -> None:
	archive = _overflowing_zip(tmp_path / "x.zip")
	destination = tmp_path / "nouveau" / "out"
	with pytest.raises(QuotaExceeded):
		Scanner(Limits(max_extract_bytes=1000)).safe_extract(archive, destination)
	assert not destination.exists()


def test_a_failed_extraction_leaves_no_empty_directory_behind(tmp_path: Path) -> None:
	archive = tmp_path / "x.zip"
	with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as handle:
		handle.writestr("profond/dossier/a.bin", bytes(range(256)) * 12)
	destination = tmp_path / "out"
	destination.mkdir()
	with pytest.raises(QuotaExceeded):
		Scanner(Limits(max_extract_bytes=1000)).safe_extract(archive, destination)
	assert list(destination.iterdir()) == []


def test_a_successful_extraction_leaves_no_working_directory(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"d/a.txt": b"aa", "b.txt": b"bbb"})
	destination = tmp_path / "out"
	Scanner().safe_extract(archive, destination)
	names = sorted(str(p.relative_to(destination)) for p in destination.rglob("*"))
	assert names == ["b.txt", "d", "d/a.txt"]


def test_a_successful_extraction_replaces_existing_files(tmp_path: Path) -> None:
	destination = tmp_path / "out"
	destination.mkdir()
	(destination / "a.txt").write_text("ancien")
	(destination / "garde.txt").write_text("garde")
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"nouveau"})
	Scanner().safe_extract(archive, destination)
	assert (destination / "a.txt").read_text() == "nouveau"
	assert (destination / "garde.txt").read_text() == "garde"


def test_the_archive_extracted_is_the_one_inspected(tmp_path: Path, monkeypatch) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"inoffensif"})
	original_inspect = Scanner.inspect

	def inspect_then_swap(self, path, **kwargs):
		verdict = original_inspect(self, path, **kwargs)
		write_zip(archive, {"a.txt": b"remplace apres le verdict"})
		return verdict

	monkeypatch.setattr(Scanner, "inspect", inspect_then_swap)
	Scanner().safe_extract(archive, tmp_path / "out")
	assert (tmp_path / "out" / "a.txt").read_bytes() == b"inoffensif"


def test_duplicate_entries_are_refused(tmp_path: Path) -> None:
	archive = tmp_path / "double.zip"
	with warnings.catch_warnings():
		warnings.simplefilter("ignore", UserWarning)
		with zipfile.ZipFile(archive, "w") as handle:
			handle.writestr("a.txt", b"vu par l'inspection")
			handle.writestr("a.txt", b"ecrit sur le disque")
	with pytest.raises(ExtractionRefused, match="double"):
		Scanner().safe_extract(archive, tmp_path / "out")
	assert not (tmp_path / "out").exists()


def test_duplicates_spelled_differently_are_refused(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "double.zip", {"d/a.txt": b"1", "d//./a.txt": b"2"})
	with pytest.raises(ExtractionRefused, match="double"):
		Scanner().safe_extract(archive, tmp_path / "out")


def test_a_path_used_as_file_and_directory_is_refused(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "conflit.zip", {"a": b"fichier", "a/b.txt": b"dedans"})
	with pytest.raises(ExtractionRefused):
		Scanner().safe_extract(archive, tmp_path / "out")


def test_a_directory_listed_twice_is_accepted(tmp_path: Path) -> None:
	archive = tmp_path / "dossiers.zip"
	with zipfile.ZipFile(archive, "w") as handle:
		handle.writestr("d/", b"")
		handle.writestr("d/a.txt", b"a")
		handle.writestr("./d/", b"")
	assert Scanner().safe_extract(archive, tmp_path / "out") == 1


def test_an_existing_directory_is_never_replaced_by_a_file(tmp_path: Path) -> None:
	destination = tmp_path / "out"
	(destination / "a.txt").mkdir(parents=True)
	(destination / "a.txt" / "dedans").write_text("garde")
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"fichier"})
	with pytest.raises(ExtractionRefused, match="dossier existe"):
		Scanner().safe_extract(archive, destination)
	assert (destination / "a.txt" / "dedans").read_text() == "garde"


def test_an_existing_file_in_place_of_a_parent_is_refused(tmp_path: Path) -> None:
	destination = tmp_path / "out"
	destination.mkdir()
	(destination / "a").write_text("garde")
	archive = write_zip(tmp_path / "ok.zip", {"b.txt": b"b", "a/c.txt": b"c"})
	with pytest.raises(ExtractionRefused, match="parent"):
		Scanner().safe_extract(archive, destination)
	assert (destination / "a").read_text() == "garde"
	assert not (destination / "b.txt").exists()


def test_symlinks_stay_refused_by_default(tmp_path: Path) -> None:
	archive = _write_tar_members(
		tmp_path / "lien.tar",
		[tarfile.TarInfo("sub/a.txt"), _symlink("lien", "sub/a.txt")],
		{"sub/a.txt": b"cible"},
	)
	with pytest.raises(ExtractionRefused, match="Lien refusé"):
		Scanner().safe_extract(archive, tmp_path / "out")


def test_an_inner_symlink_is_recreated_when_allowed(tmp_path: Path) -> None:
	archive = _write_tar_members(
		tmp_path / "lien.tar",
		[tarfile.TarInfo("sub/a.txt"), _symlink("lien", "sub/a.txt")],
		{"sub/a.txt": b"cible"},
	)
	destination = tmp_path / "out"
	Scanner().safe_extract(archive, destination, allow_links=True)
	link = destination / "lien"
	assert link.is_symlink()
	assert link.read_bytes() == b"cible"


@pytest.mark.parametrize("target", ["/etc/passwd", "../dehors", "sub/../../dehors", "C:/x", ""])
def test_an_escaping_symlink_is_refused_even_when_allowed(tmp_path: Path, target: str) -> None:
	archive = _write_tar_members(tmp_path / "lien.tar", [_symlink("lien", target)], {})
	with pytest.raises(ExtractionRefused):
		Scanner().safe_extract(archive, tmp_path / "out", allow_links=True)
	assert not (tmp_path / "out").exists()


def test_a_hardlink_is_refused_even_when_allowed(tmp_path: Path) -> None:
	hard = tarfile.TarInfo("dur")
	hard.type = tarfile.LNKTYPE
	hard.linkname = "a.txt"
	archive = _write_tar_members(
		tmp_path / "dur.tar", [tarfile.TarInfo("a.txt"), hard], {"a.txt": b"a"}
	)
	with pytest.raises(ExtractionRefused, match="physique"):
		Scanner().safe_extract(archive, tmp_path / "out", allow_links=True)


def test_nothing_is_written_through_an_archived_symlink(tmp_path: Path) -> None:
	archive = _write_tar_members(
		tmp_path / "lien.tar",
		[_symlink("lien", "sub"), tarfile.TarInfo("lien/x.txt")],
		{"lien/x.txt": b"x"},
	)
	with pytest.raises(ExtractionRefused):
		Scanner().safe_extract(archive, tmp_path / "out", allow_links=True)


def test_a_zip_symlink_is_recreated_when_allowed(tmp_path: Path) -> None:
	archive = tmp_path / "lien.zip"
	with zipfile.ZipFile(archive, "w") as handle:
		handle.writestr("a.txt", b"cible")
		info = zipfile.ZipInfo("lien")
		info.external_attr = 0o120777 << 16
		handle.writestr(info, b"a.txt")
	destination = tmp_path / "out"
	Scanner().safe_extract(archive, destination, allow_links=True)
	assert (destination / "lien").is_symlink()
	assert (destination / "lien").read_bytes() == b"cible"


def test_a_zip_symlink_escaping_is_refused_when_allowed(tmp_path: Path) -> None:
	archive = tmp_path / "lien.zip"
	with zipfile.ZipFile(archive, "w") as handle:
		info = zipfile.ZipInfo("lien")
		info.external_attr = 0o120777 << 16
		handle.writestr(info, b"../../etc/passwd")
	with pytest.raises(ExtractionRefused):
		Scanner().safe_extract(archive, tmp_path / "out", allow_links=True)
