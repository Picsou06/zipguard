from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from conftest import write_tar, write_zip

from zipguard import Limits
from zipguard.service import ScanTimeout, build_server, scan_in_worker


@pytest.fixture
def server():
	"""
	Description: Démarre un serveur ZipGuard sur un port libre, puis l'arrête proprement.
	Usage: def test_x(server): url = server("/health").
	Inputs: aucun.
	Outputs: callable transformant un chemin en URL absolue vers le serveur de test.
	"""

	httpd = build_server(
		limits=Limits(max_ratio=5.0),
		host="127.0.0.1",
		port=0,
		max_upload_bytes=200_000,
		isolate=False,
	)
	thread = threading.Thread(target=httpd.serve_forever, daemon=True)
	thread.start()
	host, port = httpd.server_address[0], httpd.server_address[1]

	def url(path: str) -> str:
		return f"http://{host}:{port}{path}"

	yield url

	httpd.shutdown()
	httpd.server_close()
	thread.join(timeout=5)


def _get(url: str):
	with urllib.request.urlopen(url, timeout=10) as response:
		return response.status, json.loads(response.read())


def _post(url: str, payload: bytes):
	request = urllib.request.Request(
		url,
		data=payload,
		method="POST",
		headers={"Content-Type": "application/octet-stream"},
	)
	with urllib.request.urlopen(request, timeout=30) as response:
		return response.status, json.loads(response.read())


def test_health_endpoint_answers(server) -> None:
	status, payload = _get(server("/health"))
	assert status == 200
	assert payload["status"] == "ok"


def test_health_endpoint_names_the_version(server) -> None:
	_, payload = _get(server("/health"))
	assert payload["version"]


def test_limits_endpoint_publishes_the_thresholds(server) -> None:
	status, payload = _get(server("/limits"))
	assert status == 200
	assert payload["max_ratio"] == 5.0


def test_scanning_a_benign_archive_returns_a_safe_verdict(server, tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"note.txt": b"bonjour le monde"})
	status, payload = _post(server("/scan"), archive.read_bytes())
	assert status == 200
	assert payload["safe"] is True


def test_scanning_a_bomb_returns_a_dangerous_verdict(server, tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "bombe.zip", {"gros.txt": b"A" * 150_000})
	_, payload = _post(server("/scan"), archive.read_bytes())
	assert payload["safe"] is False
	assert payload["reasons"]


def test_scan_response_carries_the_schema_version(server, tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"note.txt": b"bonjour"})
	_, payload = _post(server("/scan"), archive.read_bytes())
	assert payload["schema_version"] == 1


def test_a_tar_upload_is_scanned_too(server, tmp_path: Path) -> None:
	archive = write_tar(tmp_path / "ok.tar.gz", {"note.txt": b"bonjour le monde"})
	_, payload = _post(server("/scan"), archive.read_bytes())
	assert payload["stats"]["kind"] == "tar.gz"


def test_an_upload_above_the_cap_is_refused(server, tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "gros.zip", {"f.txt": bytes(range(256)) * 2000})
	payload = b"x" * 300_000
	with pytest.raises(urllib.error.HTTPError) as error:
		_post(server("/scan"), payload)
	assert error.value.code == 413
	assert archive.exists()


def test_an_empty_upload_is_refused(server) -> None:
	with pytest.raises(urllib.error.HTTPError) as error:
		_post(server("/scan"), b"")
	assert error.value.code == 400


def test_an_unknown_route_is_a_404(server) -> None:
	with pytest.raises(urllib.error.HTTPError) as error:
		_get(server("/nimportequoi"))
	assert error.value.code == 404


def test_posting_to_a_read_only_route_is_a_405(server) -> None:
	with pytest.raises(urllib.error.HTTPError) as error:
		_post(server("/limits"), b"xx")
	assert error.value.code == 405


def test_a_file_that_is_not_an_archive_gets_a_refusal_not_a_crash(server) -> None:
	_, payload = _post(server("/scan"), b"ceci n'est pas une archive")
	assert payload["safe"] is False


def test_the_worker_runs_the_scan_in_another_process(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"note.txt": b"bonjour le monde"})
	verdict = scan_in_worker(archive, Limits(), timeout=60)
	assert verdict.safe is True
	assert verdict.stats["kind"] == "zip"


def test_a_worker_that_overruns_its_deadline_is_killed(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"note.txt": b"bonjour"})
	with pytest.raises(ScanTimeout):
		scan_in_worker(archive, Limits(), timeout=0.0)


def test_the_server_binds_the_loopback_by_default() -> None:
	httpd = build_server(limits=Limits(), port=0, isolate=False)
	try:
		assert httpd.server_address[0] == "127.0.0.1"
	finally:
		httpd.server_close()
