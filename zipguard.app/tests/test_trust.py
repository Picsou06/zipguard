from __future__ import annotations

import hashlib
import json
import threading
import urllib.request
from pathlib import Path

import pytest

from conftest import write_zip
from zipguard import Limits, Scanner
from zipguard.__main__ import EXIT_OK, EXIT_UNSAFE, EXIT_USAGE, main
from zipguard.scanner import QuotaExceeded
from zipguard.service import build_server, scan_in_worker
from zipguard.trust import fingerprint, load_allowlist, parse_allowlist


def _bomb(path: Path) -> Path:
	return write_zip(path, {"donnees.csv": b"0," * 200_000})


def test_fingerprint_matches_sha256sum(tmp_path: Path) -> None:
	archive = _bomb(tmp_path / "a.zip")
	assert fingerprint(archive) == hashlib.sha256(archive.read_bytes()).hexdigest()


def test_the_allowlist_reads_sha256sum_output() -> None:
	digest = "a" * 64
	lines = [
		"# jeux de données validés",
		"",
		f"{digest.upper()}  donnees.zip",
		f"\\{'b' * 64}  nom\\nbizarre",
	]
	assert parse_allowlist(lines) == {digest, "b" * 64}


def test_a_malformed_line_is_an_error_not_a_silent_skip() -> None:
	with pytest.raises(ValueError, match="ligne 2"):
		parse_allowlist(["a" * 64, "pas-une-empreinte  x.zip"])


def test_a_trusted_archive_is_safe_without_inspection(tmp_path: Path) -> None:
	archive = _bomb(tmp_path / "donnees.zip")
	assert Scanner().inspect(archive).safe is False

	verdict = Scanner(trusted={fingerprint(archive)}).inspect(archive)
	assert verdict.safe is True
	assert verdict.stats["trusted"] is True
	assert verdict.stats["sha256"] == fingerprint(archive)
	assert "entries" not in verdict.stats


def test_an_untrusted_archive_reports_its_fingerprint(tmp_path: Path) -> None:
	archive = _bomb(tmp_path / "donnees.zip")
	verdict = Scanner(trusted={"0" * 64}).inspect(archive)
	assert verdict.safe is False
	assert verdict.stats["sha256"] == fingerprint(archive)
	assert "trusted" not in verdict.stats


def test_a_modified_archive_loses_its_trust(tmp_path: Path) -> None:
	archive = _bomb(tmp_path / "donnees.zip")
	trusted = {fingerprint(archive)}
	_bomb(tmp_path / "autre.zip")
	write_zip(archive, {"donnees.csv": b"1," * 200_000})
	assert Scanner(trusted=trusted).inspect(archive).safe is False


def test_a_trusted_nested_archive_is_accepted_inside_an_untrusted_one(tmp_path: Path) -> None:
	inner = _bomb(tmp_path / "interne.zip")
	outer = write_zip(tmp_path / "externe.zip", {"interne.zip": inner.read_bytes()})
	assert Scanner().inspect(outer).safe is False
	assert Scanner(trusted={fingerprint(inner)}).inspect(outer).safe is True


def test_trust_lifts_the_verdict_not_the_extraction_quota(tmp_path: Path) -> None:
	archive = _bomb(tmp_path / "donnees.zip")
	scanner = Scanner(Limits(max_extract_bytes=1000), trusted={fingerprint(archive)})
	with pytest.raises(QuotaExceeded):
		scanner.safe_extract(archive, tmp_path / "out")


def test_a_trusted_archive_extracts(tmp_path: Path) -> None:
	archive = _bomb(tmp_path / "donnees.zip")
	written = Scanner(trusted={fingerprint(archive)}).safe_extract(archive, tmp_path / "out")
	assert written == 400_000


def test_the_cli_trust_flag(tmp_path: Path, capsys) -> None:
	archive = _bomb(tmp_path / "donnees.zip")
	allowlist = tmp_path / "confiance.txt"

	assert main(["fingerprint", str(archive)]) == EXIT_OK
	allowlist.write_text(capsys.readouterr().out)
	assert load_allowlist(allowlist) == {fingerprint(archive)}

	assert main(["scan", str(archive), "--json"]) == EXIT_UNSAFE
	capsys.readouterr()
	assert main(["scan", str(archive), "--json", "--trust", str(allowlist)]) == EXIT_OK
	assert json.loads(capsys.readouterr().out)["stats"]["trusted"] is True


def test_an_unreadable_allowlist_is_a_usage_error(tmp_path: Path, capsys) -> None:
	archive = _bomb(tmp_path / "donnees.zip")
	bad = tmp_path / "confiance.txt"
	bad.write_text("pas une empreinte\n")
	assert main(["scan", str(archive), "--trust", str(bad)]) == EXIT_USAGE
	assert "ligne 1" in capsys.readouterr().err
	assert main(["scan", str(archive), "--trust", str(tmp_path / "absent.txt")]) == EXIT_USAGE


def test_fingerprint_of_a_missing_file_is_an_error(tmp_path: Path, capsys) -> None:
	assert main(["fingerprint", str(tmp_path / "absent.zip")]) == 3


def test_the_worker_honours_the_allowlist(tmp_path: Path) -> None:
	archive = _bomb(tmp_path / "donnees.zip")
	verdict = scan_in_worker(archive, Limits(), timeout=60, trusted=frozenset({fingerprint(archive)}))
	assert verdict.safe is True


def test_the_service_honours_the_allowlist(tmp_path: Path) -> None:
	archive = _bomb(tmp_path / "donnees.zip")
	httpd = build_server(port=0, isolate=False, trusted=frozenset({fingerprint(archive)}))
	thread = threading.Thread(target=httpd.serve_forever, daemon=True)
	thread.start()
	try:
		host, port = httpd.server_address[0], httpd.server_address[1]
		with urllib.request.urlopen(f"http://{host}:{port}/limits", timeout=10) as response:
			assert json.loads(response.read())["trusted_fingerprints"] == 1
		request = urllib.request.Request(
			f"http://{host}:{port}/scan", data=archive.read_bytes(), method="POST"
		)
		with urllib.request.urlopen(request, timeout=10) as response:
			assert json.loads(response.read())["safe"] is True
	finally:
		httpd.shutdown()
		httpd.server_close()
		thread.join(timeout=5)
