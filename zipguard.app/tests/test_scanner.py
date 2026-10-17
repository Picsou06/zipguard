from __future__ import annotations

import gzip
import zipfile
from pathlib import Path

from conftest import write_tar

from zipguard import Limits, Scanner


def _make_zip(path: Path, name: str, data: bytes) -> Path:
	with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		archive.writestr(name, data)
	return path


def test_benign_archive_is_safe(tmp_path: Path) -> None:
	archive = _make_zip(tmp_path / "ok.zip", "hello.txt", b"bonjour le monde")
	verdict = Scanner().inspect(archive)
	assert verdict.safe is True
	assert verdict.reasons == []


def test_high_ratio_is_rejected(tmp_path: Path) -> None:
	archive = _make_zip(tmp_path / "ratio.zip", "big.txt", b"A" * 5_000_000)
	verdict = Scanner(Limits(max_ratio=5.0)).inspect(archive)
	assert verdict.safe is False
	assert any("Ratio" in reason for reason in verdict.reasons)


def test_total_size_limit_is_rejected(tmp_path: Path) -> None:
	archive = _make_zip(tmp_path / "size.zip", "big.txt", b"B" * 2_000_000)
	verdict = Scanner(Limits(max_total_bytes=1_000_000, max_ratio=1_000_000)).inspect(archive)
	assert verdict.safe is False


def test_non_zip_is_rejected(tmp_path: Path) -> None:
	plain = tmp_path / "note.txt"
	plain.write_text("pas une archive")
	verdict = Scanner().inspect(plain)
	assert verdict.safe is False


def test_safe_extract_refuses_dangerous(tmp_path: Path) -> None:
	archive = _make_zip(tmp_path / "danger.zip", "big.txt", b"C" * 3_000_000)
	scanner = Scanner(Limits(max_ratio=2.0))
	try:
		scanner.safe_extract(archive, tmp_path / "out")
		assert False, "une archive dangereuse ne doit pas être extraite"
	except ValueError:
		assert True


def test_safe_extract_writes_benign(tmp_path: Path) -> None:
	archive = _make_zip(tmp_path / "ok.zip", "hello.txt", b"salut")
	written = Scanner().safe_extract(archive, tmp_path / "out")
	assert written == len(b"salut")
	assert (tmp_path / "out" / "hello.txt").read_bytes() == b"salut"


def test_tar_gz_is_inspected_like_a_zip(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "ok.tar.gz", {"hello.txt": b"bonjour le monde"})
	verdict = Scanner().inspect(archive)
	assert verdict.safe is True
	assert verdict.stats["kind"] == "tar.gz"


def test_tar_gz_bomb_is_refused_on_measured_size(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "bombe.tar.gz", {"gros.txt": b"A" * 8_000_000})
	verdict = Scanner(Limits(max_ratio=5.0)).inspect(archive)
	assert verdict.safe is False


def test_reading_beyond_the_cap_is_a_refusal_not_a_crash(tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "bombe.tar.gz", {"gros.txt": b"A" * 8_000_000})
	verdict = Scanner(Limits(max_total_bytes=1_000_000)).inspect(archive)
	assert verdict.safe is False
	assert any("coup" in reason.lower() for reason in verdict.reasons)


def test_plain_gzip_stream_is_measured(tmp_path: Path) -> None:
	path = tmp_path / "gros.txt.gz"
	with gzip.open(path, "wb") as handle:
		handle.write(b"A" * 4_000_000)
	verdict = Scanner(Limits(max_ratio=5.0)).inspect(path)
	assert verdict.safe is False
	assert verdict.stats["kind"] == "gz"


def test_stats_mention_whether_sizes_were_measured(tmp_path: Path) -> None:
	zip_archive = _make_zip(tmp_path / "a.zip", "a.txt", b"x")
	tar_archive = write_tar(tmp_path / "a.tar.gz", {"a.txt": b"x"})
	assert Scanner().inspect(zip_archive).stats["measured"] is False
	assert Scanner().inspect(tar_archive).stats["measured"] is True


def test_unsupported_file_names_the_reason(tmp_path: Path) -> None:
	plain = tmp_path / "note.txt"
	plain.write_text("pas une archive")
	verdict = Scanner().inspect(plain)
	assert verdict.safe is False
	assert verdict.stats.get("kind") is None


def test_too_many_entries_is_rejected(tmp_path: Path) -> None:
	archive = tmp_path / "beaucoup.zip"
	with zipfile.ZipFile(archive, "w") as handle:
		for i in range(50):
			handle.writestr(f"f{i}.txt", b"x")
	verdict = Scanner(Limits(max_entries=10)).inspect(archive)
	assert verdict.safe is False
	assert any("entrées" in reason for reason in verdict.reasons)


def test_biggest_entry_limit_is_rejected(tmp_path: Path) -> None:
	archive = _make_zip(tmp_path / "grosse.zip", "big.txt", b"D" * 2_000_000)
	verdict = Scanner(Limits(max_entry_bytes=1_000_000, max_ratio=10_000)).inspect(archive)
	assert verdict.safe is False


def test_missing_file_is_refused_without_crashing(tmp_path: Path) -> None:
	verdict = Scanner().inspect(tmp_path / "fantome.zip")
	assert verdict.safe is False
