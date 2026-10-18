from __future__ import annotations

import json
import multiprocessing
import pickle
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from conftest import write_zip
from zipguard import Limits, Scanner
from zipguard.service import _worker, apply_memory_limit, build_server, scan_in_worker

SRC = Path(__file__).resolve().parents[1] / "src"


@pytest.fixture
def start_server():
	"""
	Description: Démarre des serveurs ZipGuard réglables, puis les arrête tous proprement.
	Usage: host, port = start_server(read_timeout=0.5).
	Inputs: options transmises à build_server.
	Outputs: callable rendant (host, port) du serveur démarré.
	"""

	running = []

	def start(**options):
		options.setdefault("isolate", False)
		httpd = build_server(limits=Limits(), host="127.0.0.1", port=0, **options)
		thread = threading.Thread(target=httpd.serve_forever, daemon=True)
		thread.start()
		running.append((httpd, thread))
		return httpd.server_address[0], httpd.server_address[1]

	yield start

	for httpd, thread in running:
		httpd.shutdown()
		httpd.server_close()
		thread.join(timeout=5)


def _partial_upload(host: str, port: int, announced: int, sent: bytes) -> socket.socket:
	sock = socket.create_connection((host, port), timeout=10)
	sock.sendall(
		(f"POST /scan HTTP/1.1\r\nHost: {host}\r\nContent-Length: {announced}\r\n\r\n").encode() + sent
	)
	return sock


def _status_of(sock: socket.socket) -> int:
	data = b""
	while b"\r\n" not in data:
		chunk = sock.recv(4096)
		if not chunk:
			break
		data += chunk
	return int(data.split(b" ", 2)[1])


def test_a_trickling_upload_is_cut_by_the_read_timeout(start_server) -> None:
	host, port = start_server(read_timeout=0.5)
	sock = _partial_upload(host, port, 1000, b"x" * 10)
	try:
		assert _status_of(sock) == 408
	finally:
		sock.close()


def test_a_truncated_body_is_refused(start_server) -> None:
	host, port = start_server()
	sock = _partial_upload(host, port, 1000, b"x" * 10)
	try:
		sock.shutdown(socket.SHUT_WR)
		assert _status_of(sock) == 400
	finally:
		sock.close()


def test_uploads_beyond_the_concurrency_cap_get_a_503(start_server, tmp_path: Path) -> None:
	host, port = start_server(max_concurrent=1, read_timeout=10)
	holder = _partial_upload(host, port, 1000, b"x" * 10)
	try:
		time.sleep(0.3)
		archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
		request = urllib.request.Request(
			f"http://{host}:{port}/scan", data=archive.read_bytes(), method="POST"
		)
		with pytest.raises(urllib.error.HTTPError) as error:
			urllib.request.urlopen(request, timeout=10)
		assert error.value.code == 503
		assert error.value.headers["Retry-After"]
	finally:
		holder.close()


def test_a_slot_is_released_once_the_upload_is_done(start_server, tmp_path: Path) -> None:
	host, port = start_server(max_concurrent=1)
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	for _ in range(3):
		request = urllib.request.Request(
			f"http://{host}:{port}/scan", data=archive.read_bytes(), method="POST"
		)
		with urllib.request.urlopen(request, timeout=10) as response:
			assert json.loads(response.read())["safe"] is True


def test_memory_exhaustion_in_the_worker_is_a_dangerous_verdict(
	tmp_path: Path, monkeypatch
) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})

	def explode(self, path, **kwargs):
		raise MemoryError

	monkeypatch.setattr(Scanner, "inspect", explode)
	parent, child = multiprocessing.Pipe(duplex=False)
	_worker(str(archive), Limits().as_dict(), child, 0)
	status, payload = parent.recv()
	assert status == "ok"
	assert payload["safe"] is False
	assert "Mémoire" in payload["reasons"][0]


def test_a_zero_memory_limit_changes_nothing() -> None:
	assert apply_memory_limit(0) is False


@pytest.mark.skipif(
	not sys.platform.startswith("linux"), reason="RLIMIT_AS n'est fiable que sous Linux."
)
def test_the_memory_limit_is_really_applied() -> None:
	code = (
		"import resource\n"
		"from zipguard.service import apply_memory_limit\n"
		"assert apply_memory_limit(800_000_000)\n"
		"print(resource.getrlimit(resource.RLIMIT_AS)[0])\n"
	)
	result = subprocess.run(
		[sys.executable, "-c", code],
		capture_output=True,
		text=True,
		check=True,
		env={"PYTHONPATH": str(SRC)},
	)
	assert int(result.stdout.strip()) == 800_000_000


@pytest.mark.skipif(
	not sys.platform.startswith("linux"), reason="RLIMIT_AS n'est fiable que sous Linux."
)
def test_an_allocation_beyond_the_limit_fails_inside_the_process_only() -> None:
	code = (
		"from zipguard.service import apply_memory_limit\n"
		"apply_memory_limit(300_000_000)\n"
		"try:\n"
		"    bytearray(600_000_000)\n"
		"except MemoryError:\n"
		"    print('refusé')\n"
	)
	result = subprocess.run(
		[sys.executable, "-c", code],
		capture_output=True,
		text=True,
		check=True,
		env={"PYTHONPATH": str(SRC)},
	)
	assert result.stdout.strip() == "refusé"


def test_a_large_verdict_is_not_mistaken_for_a_timeout(tmp_path: Path) -> None:
	inner = write_zip(tmp_path / "interne.zip", {"a.txt": b"bonjour"})
	files = {f"fille-{index:03d}-{'x' * 400}.zip": inner.read_bytes() for index in range(150)}
	archive = write_zip(tmp_path / "beaucoup.zip", files)
	verdict = scan_in_worker(archive, Limits(max_nested_scans=200), timeout=60)
	# Au delà de 64 Kio, le tampon du tube est plein et le worker attend qu'on le lise.
	assert len(pickle.dumps(("ok", verdict.as_dict()))) > 65536
	assert len(verdict.children) == 150
