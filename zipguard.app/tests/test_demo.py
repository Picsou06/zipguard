from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from zipguard import Scanner
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
