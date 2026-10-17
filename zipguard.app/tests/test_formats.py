from __future__ import annotations

from pathlib import Path

import pytest

from conftest import write_tar, write_zip
from zipguard.formats import (
	ReadCapExceeded,
	UnsupportedArchive,
	detect_kind,
	open_archive,
	sniff_kind,
)


def test_detects_zip_by_content_not_extension(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "deguise.bin", {"a.txt": b"bonjour"})
	assert detect_kind(archive) == "zip"


def test_detects_gzipped_tar(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "a.tar.gz", {"a.txt": b"bonjour"})
	assert detect_kind(archive) == "tar.gz"


def test_detects_plain_tar(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "a.tar", {"a.txt": b"bonjour"}, mode="w")
	assert detect_kind(archive) == "tar"


def test_detects_xz_tar(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "a.tar.xz", {"a.txt": b"bonjour"}, mode="w:xz")
	assert detect_kind(archive) == "tar.xz"


def test_detects_bzip2_tar(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "a.tar.bz2", {"a.txt": b"bonjour"}, mode="w:bz2")
	assert detect_kind(archive) == "tar.bz2"


def test_unknown_content_is_not_an_archive(tmp_path: Path) -> None:
	plain = tmp_path / "note.txt"
	plain.write_text("pas une archive")
	assert detect_kind(plain) is None


def test_open_archive_lists_zip_entries(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "a.zip", {"a.txt": b"bonjour", "b.txt": b"salut"})
	with open_archive(archive) as handle:
		names = sorted(entry.name for entry in handle.entries())
		assert names == ["a.txt", "b.txt"]


def test_open_archive_lists_tar_entries(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "a.tar.gz", {"a.txt": b"bonjour", "b.txt": b"salut"})
	with open_archive(archive) as handle:
		names = sorted(entry.name for entry in handle.entries())
		assert names == ["a.txt", "b.txt"]


def test_zip_entry_reports_declared_sizes(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "a.zip", {"a.txt": b"A" * 100_000})
	with open_archive(archive) as handle:
		entry = handle.entries()[0]
		assert entry.size == 100_000
		assert 0 < entry.compressed_size < 100_000


def test_tar_compressed_total_is_the_file_size(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "a.tar.gz", {"a.txt": b"A" * 100_000})
	with open_archive(archive) as handle:
		handle.entries()
		assert handle.compressed_total == archive.stat().st_size


def test_reading_an_entry_returns_its_bytes(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "a.tar.gz", {"a.txt": b"bonjour"})
	with open_archive(archive) as handle:
		entry = handle.entries()[0]
		with handle.open(entry) as stream:
			assert stream.read() == b"bonjour"


def test_listing_a_tar_stops_at_the_read_cap(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "bombe.tar.gz", {"gros.txt": b"A" * 5_000_000})
	with open_archive(archive, read_cap=1_000_000) as handle, pytest.raises(ReadCapExceeded):
		handle.entries()


def test_unsupported_file_raises(tmp_path: Path) -> None:
	plain = tmp_path / "note.txt"
	plain.write_text("pas une archive")
	with pytest.raises(UnsupportedArchive):
		open_archive(plain)


def test_tar_entries_know_their_directories(tmp_path: Path) -> None:
	import io
	import tarfile

	path = tmp_path / "a.tar"
	with tarfile.open(path, "w") as archive:
		folder = tarfile.TarInfo("dossier")
		folder.type = tarfile.DIRTYPE
		archive.addfile(folder)
		info = tarfile.TarInfo("dossier/a.txt")
		info.size = 3
		archive.addfile(info, io.BytesIO(b"abc"))

	with open_archive(path) as handle:
		entries = {entry.name: entry for entry in handle.entries()}
		assert entries["dossier"].is_dir is True
		assert entries["dossier/a.txt"].is_dir is False


def test_sniff_kind_recognises_a_zip_header() -> None:
	assert sniff_kind(b"PKrest of the header") == "zip"


def test_sniff_kind_ignores_plain_text() -> None:
	assert sniff_kind(b"ceci est du texte") is None


def test_head_returns_the_first_bytes_of_an_entry(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "a.zip", {"a.txt": b"bonjour le monde"})
	with open_archive(archive) as handle:
		assert handle.head(handle.entries()[0], 7) == b"bonjour"


def test_head_on_tar_does_not_rescan_the_whole_stream(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "a.tar.gz", {"a.txt": b"bonjour le monde"})
	with open_archive(archive) as handle:
		entries = handle.entries()
		assert handle.head(entries[0], 7) == b"bonjour"


def test_zip_symlink_entry_is_flagged(tmp_path: Path) -> None:
	import zipfile

	path = tmp_path / "lien.zip"
	with zipfile.ZipFile(path, "w") as handle:
		info = zipfile.ZipInfo("lien")
		info.external_attr = 0o120777 << 16
		handle.writestr(info, "/etc/passwd")
	with open_archive(path) as handle:
		assert handle.entries()[0].is_link is True


def test_tar_symlink_entry_is_flagged(tmp_path: Path) -> None:
	import tarfile

	path = tmp_path / "lien.tar"
	with tarfile.open(path, "w") as handle:
		info = tarfile.TarInfo("lien")
		info.type = tarfile.SYMTYPE
		info.linkname = "/etc/passwd"
		handle.addfile(info)
	with open_archive(path) as handle:
		assert handle.entries()[0].is_link is True
