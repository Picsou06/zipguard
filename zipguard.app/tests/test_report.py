from __future__ import annotations

import json
import re
from pathlib import Path

from conftest import write_zip
from zipguard import Limits, Scanner, render, render_json
from zipguard.report import glyphs_supported

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _safe_verdict(tmp_path: Path):
	archive = write_zip(tmp_path / "ok.zip", {"hello.txt": b"bonjour le monde"})
	return archive, Scanner().inspect(archive)


def _dangerous_verdict(tmp_path: Path):
	archive = write_zip(tmp_path / "bombe.zip", {"gros.txt": b"A" * 5_000_000})
	return archive, Scanner(Limits(max_ratio=5.0)).inspect(archive)


def test_report_names_the_archive(tmp_path: Path) -> None:
	archive, verdict = _safe_verdict(tmp_path)
	assert "ok.zip" in render(str(archive), verdict, color=False)


def test_safe_report_says_so(tmp_path: Path) -> None:
	_, verdict = _safe_verdict(tmp_path)
	assert "SÛRE" in render("ok.zip", verdict, color=False)


def test_dangerous_report_lists_every_reason(tmp_path: Path) -> None:
	_, verdict = _dangerous_verdict(tmp_path)
	text = render("bombe.zip", verdict, color=False)
	assert "DANGEREUSE" in text
	for reason in verdict.reasons:
		assert reason in text


def test_report_shows_the_format_it_detected(tmp_path: Path) -> None:
	_, verdict = _safe_verdict(tmp_path)
	assert "zip" in render("ok.zip", verdict, color=False)


def test_report_draws_a_ratio_gauge(tmp_path: Path) -> None:
	_, verdict = _dangerous_verdict(tmp_path)
	assert "█" in render("bombe.zip", verdict, color=False, limits=Limits(max_ratio=5.0))


def test_report_without_colour_has_no_escape_codes(tmp_path: Path) -> None:
	_, verdict = _dangerous_verdict(tmp_path)
	text = render("bombe.zip", verdict, color=False)
	assert ANSI.search(text) is None


def test_report_with_colour_has_escape_codes(tmp_path: Path) -> None:
	_, verdict = _dangerous_verdict(tmp_path)
	text = render("bombe.zip", verdict, color=True)
	assert ANSI.search(text) is not None


def test_no_color_environment_variable_is_honoured(tmp_path: Path, monkeypatch) -> None:
	monkeypatch.setenv("NO_COLOR", "1")
	_, verdict = _dangerous_verdict(tmp_path)
	assert ANSI.search(render("bombe.zip", verdict)) is None


def test_report_shows_nested_archives_by_name(tmp_path: Path) -> None:
	import zipfile

	inner = write_zip(tmp_path / "interne.zip", {"gros.txt": b"A" * 5_000_000})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(inner, "interne.zip")

	verdict = Scanner(Limits(max_ratio=5.0, max_depth=2)).inspect(outer)
	text = render("externe.zip", verdict, color=False)
	assert "interne.zip" in text


def test_json_report_is_valid_json(tmp_path: Path) -> None:
	_, verdict = _safe_verdict(tmp_path)
	payload = json.loads(render_json("ok.zip", verdict))
	assert payload["safe"] is True
	assert payload["archive"] == "ok.zip"


def test_json_report_carries_a_schema_version(tmp_path: Path) -> None:
	_, verdict = _safe_verdict(tmp_path)
	payload = json.loads(render_json("ok.zip", verdict))
	assert payload["schema_version"] == 1
	assert payload["tool"] == "zipguard"


def test_json_report_lists_reasons_and_stats(tmp_path: Path) -> None:
	_, verdict = _dangerous_verdict(tmp_path)
	payload = json.loads(render_json("bombe.zip", verdict))
	assert payload["safe"] is False
	assert payload["reasons"] == verdict.reasons
	assert payload["stats"]["kind"] == "zip"


def test_json_report_nests_children(tmp_path: Path) -> None:
	import zipfile

	inner = write_zip(tmp_path / "interne.zip", {"gros.txt": b"A" * 5_000_000})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(inner, "interne.zip")

	verdict = Scanner(Limits(max_ratio=5.0, max_depth=2)).inspect(outer)
	payload = json.loads(render_json("externe.zip", verdict))
	assert payload["children"][0]["stats"]["name"] == "interne.zip"


def test_json_report_can_embed_the_limits(tmp_path: Path) -> None:
	_, verdict = _safe_verdict(tmp_path)
	payload = json.loads(render_json("ok.zip", verdict, limits=Limits(max_ratio=42.0)))
	assert payload["limits"]["max_ratio"] == 42.0


def test_json_report_is_a_single_line_when_compact(tmp_path: Path) -> None:
	_, verdict = _safe_verdict(tmp_path)
	assert "\n" not in render_json("ok.zip", verdict, indent=None)


class _FakeStream:
	"""Flux minimal servant à simuler une console avec un encodage donné."""

	def __init__(self, encoding: str) -> None:
		self.encoding = encoding

	def isatty(self) -> bool:
		return True


def test_glyphs_are_supported_on_a_utf8_console() -> None:
	assert glyphs_supported(_FakeStream("utf-8")) is True


def test_glyphs_are_not_supported_on_a_cp1252_console() -> None:
	assert glyphs_supported(_FakeStream("cp1252")) is False


def test_report_falls_back_to_ascii_when_asked(tmp_path: Path) -> None:
	_, verdict = _dangerous_verdict(tmp_path)
	text = render("bombe.zip", verdict, color=False, unicode=False)
	assert "⛔" not in text
	assert "█" not in text
	assert "DANGEREUSE" in text


def test_ascii_report_still_draws_a_gauge(tmp_path: Path) -> None:
	_, verdict = _dangerous_verdict(tmp_path)
	text = render("bombe.zip", verdict, color=False, unicode=False, limits=Limits(max_ratio=5.0))
	assert "#" in text


def test_ascii_report_keeps_accented_french(tmp_path: Path) -> None:
	_, verdict = _safe_verdict(tmp_path)
	text = render("ok.zip", verdict, color=False, unicode=False)
	assert "SÛRE" in text
	assert text.encode("cp1252")


def test_ascii_report_still_names_nested_archives(tmp_path: Path) -> None:
	import zipfile

	inner = write_zip(tmp_path / "interne.zip", {"gros.txt": b"A" * 5_000_000})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(inner, "interne.zip")
	verdict = Scanner(Limits(max_ratio=5.0, max_depth=2)).inspect(outer)
	text = render("externe.zip", verdict, color=False, unicode=False)
	assert "interne.zip" in text
	assert text.encode("cp1252")


def test_escape_sequences_from_an_archive_never_reach_the_terminal(tmp_path) -> None:
	import io
	import zipfile

	from zipguard import Scanner
	from zipguard.report import render

	inner = io.BytesIO()
	with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as handle:
		handle.writestr("a.txt", b"A" * 2_000_000)
	archive = tmp_path / "piege.zip"
	with zipfile.ZipFile(archive, "w") as handle:
		handle.writestr("x\x1b[2K\x1b[1A\r   SURE\x1b[8m‮txt.exe", inner.getvalue())

	output = render(str(archive), Scanner().inspect(archive), color=False)
	assert "\x1b" not in output
	assert "‮" not in output
	assert "\\x1b[2K" in output
	assert "\\u202e" in output


def test_printable_keeps_ordinary_text() -> None:
	from zipguard.report import printable

	assert printable("données/été ✅.zip") == "données/été ✅.zip"
	assert printable("a\nb\tc\x00") == "a\\x0ab\\x09c\\x00"


def test_extraction_errors_are_printed_safely(tmp_path, capsys) -> None:
	import zipfile

	from zipguard.__main__ import main

	archive = tmp_path / "piege.zip"
	with zipfile.ZipFile(archive, "w") as handle:
		handle.writestr("../\x1b]0;titre\x07evade.txt", b"x")
	assert main(["extract", str(archive), str(tmp_path / "out"), "--no-color"]) == 1
	output = capsys.readouterr().out
	assert "\x1b" not in output
	assert "\x07" not in output
