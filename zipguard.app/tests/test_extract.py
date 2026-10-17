from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from conftest import write_tar, write_zip
from zipguard import Limits, Scanner
from zipguard.scanner import ExtractionRefused, QuotaExceeded


def test_extraction_writes_benign_zip(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"hello.txt": b"salut"})
	written = Scanner().safe_extract(archive, tmp_path / "out")
	assert written == 5
	assert (tmp_path / "out" / "hello.txt").read_bytes() == b"salut"


def test_extraction_writes_benign_tar(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "ok.tar.gz", {"hello.txt": b"salut"})
	written = Scanner().safe_extract(archive, tmp_path / "out")
	assert written == 5
	assert (tmp_path / "out" / "hello.txt").read_bytes() == b"salut"


def test_extraction_refuses_a_dangerous_archive(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "danger.zip", {"gros.txt": b"C" * 3_000_000})
	with pytest.raises(ExtractionRefused):
		Scanner(Limits(max_ratio=2.0)).safe_extract(archive, tmp_path / "out")


def test_quota_stops_extraction_before_filling_the_disk(tmp_path: Path) -> None:
	archive = write_zip(
		tmp_path / "gros.zip",
		{f"f{i}.txt": bytes(range(256)) * 400 for i in range(10)},
	)
	scanner = Scanner(Limits(max_ratio=10_000, max_extract_bytes=200_000))
	with pytest.raises(QuotaExceeded):
		scanner.safe_extract(archive, tmp_path / "out")


def test_quota_breach_leaves_no_partial_files_behind(tmp_path: Path) -> None:
	archive = write_zip(
		tmp_path / "gros.zip",
		{f"f{i}.txt": bytes(range(256)) * 400 for i in range(10)},
	)
	destination = tmp_path / "out"
	scanner = Scanner(Limits(max_ratio=10_000, max_extract_bytes=200_000))
	with pytest.raises(QuotaExceeded):
		scanner.safe_extract(archive, destination)
	assert list(destination.rglob("*.txt")) == []


def test_free_space_margin_is_honoured(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"hello.txt": b"salut"})
	scanner = Scanner(Limits(min_free_bytes=10**18))
	with pytest.raises(QuotaExceeded):
		scanner.safe_extract(archive, tmp_path / "out")


def test_zip_slip_is_refused(tmp_path: Path) -> None:
	archive = tmp_path / "slip.zip"
	with zipfile.ZipFile(archive, "w") as handle:
		handle.writestr("../evade.txt", b"dehors")
	with pytest.raises(ExtractionRefused):
		Scanner().safe_extract(archive, tmp_path / "out")


def test_absolute_path_in_tar_is_refused(tmp_path: Path) -> None:
	archive = tmp_path / "absolu.tar"
	with tarfile.open(archive, "w") as handle:
		info = tarfile.TarInfo("/etc/passwd")
		info.size = 3
		handle.addfile(info, io.BytesIO(b"abc"))
	with pytest.raises(ExtractionRefused):
		Scanner().safe_extract(archive, tmp_path / "out")


def test_symlink_entry_is_refused(tmp_path: Path) -> None:
	archive = tmp_path / "lien.tar"
	with tarfile.open(archive, "w") as handle:
		info = tarfile.TarInfo("lien")
		info.type = tarfile.SYMTYPE
		info.linkname = "/etc/passwd"
		handle.addfile(info)
	with pytest.raises(ExtractionRefused):
		Scanner().safe_extract(archive, tmp_path / "out")


def test_extraction_reports_the_bytes_it_wrote(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"aa", "b.txt": b"bbb"})
	assert Scanner().safe_extract(archive, tmp_path / "out") == 5
