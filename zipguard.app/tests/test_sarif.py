from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import write_zip
from zipguard import Limits, Scanner
from zipguard.__main__ import EXIT_ERROR, EXIT_OK, EXIT_UNSAFE, main
from zipguard.limits import REASON_CODES
from zipguard.sarif import render_sarif, rule_id


def _repo(root: Path) -> Path:
	(root / "lib").mkdir(parents=True)
	(root / ".git").mkdir()
	write_zip(root / "lib" / "ok.zip", {"a.txt": b"bonjour"})
	write_zip(root / "lib" / "bombe.zip", {"a.txt": b"A" * 300_000})
	write_zip(root / ".git" / "ignore.zip", {"a.txt": b"A" * 300_000})
	(root / "lib" / "notes.txt").write_text("pas une archive")
	return root


def test_every_reason_code_has_a_rule() -> None:
	document = json.loads(render_sarif([]))
	rules = {rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]}
	assert rules == {rule_id(code) for code in REASON_CODES}


def test_the_document_is_sarif_2_1_0() -> None:
	document = json.loads(render_sarif([]))
	assert document["version"] == "2.1.0"
	assert document["runs"][0]["tool"]["driver"]["name"] == "ZipGuard"


def test_one_result_per_reason(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "gros.zip", {"a.txt": b"A" * 300_000})
	verdict = Scanner(Limits(max_ratio=2.0, max_entry_bytes=1000)).inspect(archive)
	results = json.loads(render_sarif([("lib/gros.zip", verdict)]))["runs"][0]["results"]
	assert sorted(result["ruleId"] for result in results) == ["zipguard/entry_size", "zipguard/ratio"]
	location = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]
	assert location == {"uri": "lib/gros.zip", "uriBaseId": "%SRCROOT%"}


def test_a_safe_archive_produces_no_result(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	document = json.loads(render_sarif([("ok.zip", Scanner().inspect(archive))]))
	assert document["runs"][0]["results"] == []


def test_findings_have_stable_fingerprints(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "gros.zip", {"a.txt": b"A" * 300_000})
	verdict = Scanner().inspect(archive)
	first = json.loads(render_sarif([("gros.zip", verdict)]))["runs"][0]["results"]
	second = json.loads(render_sarif([("gros.zip", verdict)]))["runs"][0]["results"]
	assert first[0]["partialFingerprints"] == second[0]["partialFingerprints"]


def test_scanning_a_directory_finds_archives_by_signature(
	tmp_path: Path, monkeypatch, capsys
) -> None:
	monkeypatch.chdir(_repo(tmp_path / "depot"))
	assert main(["scan", ".", "--sarif"]) == EXIT_UNSAFE
	results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
	assert [
		result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in results
	] == ["lib/bombe.zip"]


def test_exit_zero_lets_ci_publish_the_report(tmp_path: Path, monkeypatch, capsys) -> None:
	monkeypatch.chdir(_repo(tmp_path / "depot"))
	assert main(["scan", ".", "--sarif", "--exit-zero"]) == EXIT_OK


def test_several_archives_give_a_json_list(tmp_path: Path, capsys) -> None:
	root = _repo(tmp_path / "depot")
	ok, bomb = root / "lib" / "ok.zip", root / "lib" / "bombe.zip"
	assert main(["scan", str(ok), str(bomb), "--json"]) == EXIT_UNSAFE
	payload = json.loads(capsys.readouterr().out)
	assert [item["safe"] for item in payload] == [True, False]


def test_a_single_archive_keeps_the_json_object(tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	assert main(["scan", str(archive), "--json"]) == EXIT_OK
	assert json.loads(capsys.readouterr().out)["safe"] is True


def test_a_directory_always_gives_a_json_list(tmp_path: Path, capsys) -> None:
	(tmp_path / "d").mkdir()
	write_zip(tmp_path / "d" / "ok.zip", {"a.txt": b"bonjour"})
	assert main(["scan", str(tmp_path / "d"), "--json"]) == EXIT_OK
	assert isinstance(json.loads(capsys.readouterr().out), list)


def test_an_empty_directory_is_not_an_error(tmp_path: Path, capsys) -> None:
	(tmp_path / "vide").mkdir()
	assert main(["scan", str(tmp_path / "vide")]) == EXIT_OK
	assert "Aucune archive" in capsys.readouterr().out


def test_a_missing_target_among_several_is_an_error(tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	assert main(["scan", str(archive), str(tmp_path / "absent.zip")]) == EXIT_ERROR


@pytest.mark.parametrize("flag", ["--sarif", "--json"])
def test_symlinked_directories_are_not_followed(tmp_path: Path, monkeypatch, capsys, flag) -> None:
	outside = tmp_path / "dehors"
	outside.mkdir()
	write_zip(outside / "bombe.zip", {"a.txt": b"A" * 300_000})
	inside = tmp_path / "depot"
	inside.mkdir()
	(inside / "lien").symlink_to(outside, target_is_directory=True)
	monkeypatch.chdir(inside)
	assert main(["scan", ".", flag]) == EXIT_OK
