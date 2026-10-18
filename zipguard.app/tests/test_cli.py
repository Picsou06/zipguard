from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import write_tar, write_zip
from zipguard.__main__ import EXIT_ERROR, EXIT_OK, EXIT_UNSAFE, main


def test_scanning_a_benign_archive_exits_zero(tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"note.txt": b"bonjour le monde"})
	assert main(["scan", str(archive)]) == EXIT_OK
	assert "SÛRE" in capsys.readouterr().out


def test_scanning_a_bomb_exits_one(tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "bombe.zip", {"gros.txt": b"A" * 5_000_000})
	assert main(["scan", str(archive), "--max-ratio", "5"]) == EXIT_UNSAFE
	assert "DANGEREUSE" in capsys.readouterr().out


def test_scanning_a_missing_file_exits_three(tmp_path: Path, capsys) -> None:
	assert main(["scan", str(tmp_path / "fantome.zip")]) == EXIT_ERROR
	assert "introuvable" in capsys.readouterr().err.lower()


def test_scan_json_output_is_machine_readable(tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "bombe.zip", {"gros.txt": b"A" * 5_000_000})
	code = main(["scan", str(archive), "--max-ratio", "5", "--json"])
	payload = json.loads(capsys.readouterr().out)
	assert code == EXIT_UNSAFE
	assert payload["safe"] is False
	assert payload["limits"]["max_ratio"] == 5.0


def test_scan_accepts_a_tar_gz(tmp_path: Path, capsys) -> None:
	archive = write_tar(tmp_path / "ok.tar.gz", {"note.txt": b"bonjour le monde"})
	assert main(["scan", str(archive)]) == EXIT_OK
	assert "tar.gz" in capsys.readouterr().out


def test_scan_depth_flag_is_honoured(tmp_path: Path, capsys) -> None:
	import zipfile

	inner = write_zip(tmp_path / "interne.zip", {"gros.txt": b"A" * 5_000_000})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(inner, "interne.zip")

	code = main(["scan", str(outer), "--max-ratio", "5", "--max-depth", "0"])
	assert code == EXIT_UNSAFE
	assert "profondeur" in capsys.readouterr().out.lower()


def test_ascii_flag_removes_the_pictograms(tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"note.txt": b"bonjour"})
	main(["scan", str(archive), "--ascii"])
	out = capsys.readouterr().out
	assert "✅" not in out
	assert "[OK]" in out


def test_extracting_a_benign_archive_writes_the_files(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"note.txt": b"bonjour"})
	destination = tmp_path / "out"
	assert main(["extract", str(archive), str(destination)]) == EXIT_OK
	assert (destination / "note.txt").read_bytes() == b"bonjour"


def test_extracting_a_bomb_is_refused(tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "bombe.zip", {"gros.txt": b"A" * 5_000_000})
	code = main(["extract", str(archive), str(tmp_path / "out"), "--max-ratio", "5"])
	assert code == EXIT_UNSAFE
	assert "refus" in capsys.readouterr().out.lower()


def test_extract_json_reports_the_bytes_written(tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"note.txt": b"bonjour"})
	code = main(["extract", str(archive), str(tmp_path / "out"), "--json"])
	payload = json.loads(capsys.readouterr().out)
	assert code == EXIT_OK
	assert payload["written_bytes"] == 7


def test_extract_honours_the_extraction_quota(tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"note.txt": b"A" * 100_000})
	code = main(
		[
			"extract",
			str(archive),
			str(tmp_path / "out"),
			"--max-extract-mb",
			"0",
		]
	)
	assert code == EXIT_UNSAFE


def test_demo_builds_a_zip(tmp_path: Path, capsys) -> None:
	target = tmp_path / "demo.zip"
	assert main(["demo", str(target), "--mb", "2"]) == EXIT_OK
	assert target.is_file()
	assert "ratio" in capsys.readouterr().out


def test_demo_builds_a_tar_gz(tmp_path: Path) -> None:
	target = tmp_path / "demo.tar.gz"
	assert main(["demo", str(target), "--mb", "2", "--format", "tar.gz"]) == EXIT_OK
	assert target.is_file()


def test_demo_beyond_the_cap_is_an_error(tmp_path: Path, capsys) -> None:
	code = main(["demo", str(tmp_path / "trop.zip"), "--mb", "500"])
	assert code == EXIT_ERROR
	assert "plafonn" in capsys.readouterr().err.lower()


def test_bench_runs_and_exits_zero(capsys) -> None:
	assert main(["bench", "--repeat", "1"]) == EXIT_OK
	out = capsys.readouterr().out
	assert "banc d'essai" in out
	assert "ratio" in out


def test_bench_json_is_machine_readable(capsys) -> None:
	assert main(["bench", "--repeat", "1", "--json"]) == EXIT_OK
	payload = json.loads(capsys.readouterr().out)
	assert payload["summary"]["unexpected"] == 0


def test_bench_keeps_the_corpus_when_asked(tmp_path: Path) -> None:
	corpus = tmp_path / "corpus"
	main(["bench", "--repeat", "1", "--keep", str(corpus)])
	assert list(corpus.glob("*.zip"))


def test_version_flag_prints_the_version(capsys) -> None:
	with pytest.raises(SystemExit) as exit_info:
		main(["--version"])
	assert exit_info.value.code == 0
	assert capsys.readouterr().out.strip()


def test_no_command_is_a_usage_error() -> None:
	with pytest.raises(SystemExit) as exit_info:
		main([])
	assert exit_info.value.code == 2


def test_formats_command_lists_what_is_supported(capsys) -> None:
	assert main(["formats"]) == EXIT_OK
	out = capsys.readouterr().out
	assert "tar.gz" in out
	assert "7z" in out


def test_extract_allow_links_recreates_an_inner_symlink(tmp_path: Path, capsys) -> None:
	import io
	import tarfile

	archive = tmp_path / "lien.tar"
	with tarfile.open(archive, "w") as handle:
		info = tarfile.TarInfo("a.txt")
		info.size = 1
		handle.addfile(info, io.BytesIO(b"a"))
		link = tarfile.TarInfo("lien")
		link.type = tarfile.SYMTYPE
		link.linkname = "a.txt"
		handle.addfile(link)

	destination = tmp_path / "out"
	assert main(["extract", str(archive), str(destination), "--json"]) == EXIT_UNSAFE
	capsys.readouterr()
	assert main(["extract", str(archive), str(destination), "--json", "--allow-links"]) == EXIT_OK
	assert (destination / "lien").is_symlink()


def test_serve_accepts_the_hardening_flags() -> None:
	from zipguard.__main__ import _build_parser

	args = _build_parser().parse_args(
		["serve", "--read-timeout", "5", "--max-concurrent", "2", "--max-memory-mb", "256"]
	)
	assert (args.read_timeout, args.max_concurrent, args.max_memory_mb) == (5.0, 2, 256)
