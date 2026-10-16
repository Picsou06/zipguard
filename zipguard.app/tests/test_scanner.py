from __future__ import annotations

import zipfile
from pathlib import Path

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
