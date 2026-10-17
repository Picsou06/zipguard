from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from zipguard import Scanner, detect_kind
from zipguard.demo import SAFE_CAP_BYTES, build_demo_archive


def test_demo_is_bounded(tmp_path: Path) -> None:
	result = build_demo_archive(tmp_path / "demo.zip", text="zizi", megabytes=5)
	assert result["uncompressed"] <= 5_000_000 + 10
	assert result["compressed"] > 0
	assert result["ratio"] > 1


def test_demo_cap_is_enforced(tmp_path: Path) -> None:
	with pytest.raises(ValueError):
		build_demo_archive(tmp_path / "too_big.zip", megabytes=SAFE_CAP_BYTES // 1_000_000 + 1)


def test_demo_rejects_zero(tmp_path: Path) -> None:
	with pytest.raises(ValueError):
		build_demo_archive(tmp_path / "zero.zip", megabytes=0)


def test_demo_decompresses_to_declared_size(tmp_path: Path) -> None:
	path = tmp_path / "demo.zip"
	result = build_demo_archive(path, text="zizi", megabytes=3)
	with zipfile.ZipFile(path) as archive:
		info = archive.infolist()[0]
		assert info.file_size == result["uncompressed"]


def test_demo_output_passes_scanner_with_wide_limits(tmp_path: Path) -> None:
	path = tmp_path / "demo.zip"
	build_demo_archive(path, megabytes=2)
	verdict = Scanner().inspect(path)
	assert verdict.stats["entries"] == 1


def test_demo_can_build_a_tar_gz(tmp_path: Path) -> None:
	path = tmp_path / "demo.tar.gz"
	result = build_demo_archive(path, text="motif", megabytes=3, archive_format="tar.gz")
	assert detect_kind(path) == "tar.gz"
	assert result["format"] == "tar.gz"


def test_demo_tar_gz_respects_the_cap(tmp_path: Path) -> None:
	with pytest.raises(ValueError):
		build_demo_archive(
			tmp_path / "trop.tar.gz",
			megabytes=SAFE_CAP_BYTES // 1_000_000 + 1,
			archive_format="tar.gz",
		)


def test_demo_rejects_an_unknown_format(tmp_path: Path) -> None:
	with pytest.raises(ValueError):
		build_demo_archive(tmp_path / "demo.rar", archive_format="rar")


def test_demo_tar_gz_is_scannable(tmp_path: Path) -> None:
	path = tmp_path / "demo.tar.gz"
	build_demo_archive(path, megabytes=2, archive_format="tar.gz")
	verdict = Scanner().inspect(path)
	assert verdict.stats["kind"] == "tar.gz"
	assert verdict.stats["entries"] == 1


def test_demo_zip_result_names_its_format(tmp_path: Path) -> None:
	result = build_demo_archive(tmp_path / "demo.zip", megabytes=2)
	assert result["format"] == "zip"
