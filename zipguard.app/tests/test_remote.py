from __future__ import annotations

import contextlib
import io
import json
import os
import tarfile
import tempfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from conftest import write_tar, write_zip
from zipguard import Limits, Scanner
from zipguard.__main__ import EXIT_ERROR, EXIT_OK, EXIT_UNSAFE, main
from zipguard.remote import RemoteError, RemoteSource


class _Files:
	"""
	Description: Serveur HTTP de test, avec ou sans lecture par plages.
	Usage: url = files.add("a.zip", data).
	Inputs: aucun.
	Outputs: objet tenant les fichiers servis et des compteurs de trafic.
	"""

	def __init__(self) -> None:
		self.blobs: dict[str, bytes] = {}
		self.ranges = True
		self.announce_length = True
		self.encoding: str | None = None
		self.etags: dict[str, str] = {}
		self.authorizations: list[str | None] = []
		self.redirect_to: str | None = None
		self.redirects: dict[str, str] = {}
		self.requests = 0
		self.httpd: ThreadingHTTPServer | None = None

	def add(self, name: str, data: bytes) -> str:
		self.blobs[name] = data
		host, port = self.httpd.server_address[0], self.httpd.server_address[1]
		return f"http://{host}:{port}/{name}"


@pytest.fixture
def files():
	state = _Files()

	class Handler(BaseHTTPRequestHandler):
		def log_message(self, *args) -> None:
			pass

		def do_GET(self) -> None:
			state.requests += 1
			state.authorizations.append(self.headers.get("Authorization"))
			if state.redirect_to:
				self.send_response(302)
				self.send_header("Location", state.redirect_to)
				self.end_headers()
				return
			name = self.path.lstrip("/")
			if name in state.redirects:
				self.send_response(302)
				self.send_header("Location", state.redirects[name])
				self.end_headers()
				return
			blob = state.blobs.get(name)
			if blob is None:
				self.send_error(404)
				return
			header = self.headers.get("Range")
			validator = self.headers.get("If-Range")
			if validator is not None and validator != state.etags.get(name):
				header = None
			start = 0
			if header and state.ranges:
				start = int(header.removeprefix("bytes=").split("-")[0])
				self.send_response(206)
				self.send_header("Content-Range", f"bytes {start}-{len(blob) - 1}/{len(blob)}")
			else:
				self.send_response(200)
			body = blob[start:]
			if state.announce_length:
				self.send_header("Content-Length", str(len(body)))
			if state.encoding:
				self.send_header("Content-Encoding", state.encoding)
			if name in state.etags:
				self.send_header("ETag", state.etags[name])
			self.end_headers()
			with contextlib.suppress(BrokenPipeError, ConnectionResetError):
				self.wfile.write(body)

	httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
	httpd.daemon_threads = True
	state.httpd = httpd
	thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
	thread.start()
	yield state
	httpd.shutdown()
	httpd.server_close()
	thread.join(timeout=5)


@pytest.fixture
def no_disk(monkeypatch):
	"""
	Description: Fait échouer toute création de fichier temporaire pendant le test.
	Usage: def test_x(no_disk): ...
	Inputs: aucun.
	Outputs: None ; une tentative d'écriture temporaire lève AssertionError.
	"""

	def forbidden(*args, **kwargs):
		raise AssertionError("L'inspection distante a tenté d'écrire sur le disque.")

	monkeypatch.setattr(tempfile, "mkdtemp", forbidden)
	monkeypatch.setattr(tempfile, "mkstemp", forbidden)
	monkeypatch.setattr(tempfile, "NamedTemporaryFile", forbidden)


def _big_zip(tmp_path: Path) -> bytes:
	noise = os.urandom(3_000_000)
	archive = tmp_path / "gros.zip"
	write_zip(archive, {"bruit.bin": noise, "lisez-moi.txt": b"bonjour"})
	return archive.read_bytes()


def test_a_remote_zip_is_judged_from_a_fraction_of_its_bytes(
	files, tmp_path: Path, no_disk
) -> None:
	url = files.add("gros.zip", _big_zip(tmp_path))
	source = RemoteSource(url)
	verdict = Scanner().inspect(source)
	assert verdict.safe is True
	assert source.seekable is True
	assert verdict.stats["downloaded_bytes"] < verdict.stats["source_size"] / 50


def test_a_remote_bomb_is_refused(files, tmp_path: Path, no_disk) -> None:
	archive = write_zip(tmp_path / "bombe.zip", {"a.txt": b"A" * 2_000_000})
	verdict = Scanner().inspect(RemoteSource(files.add("bombe.zip", archive.read_bytes())))
	assert verdict.safe is False
	assert "ratio" in verdict.codes


def test_a_remote_nested_bomb_is_inspected_in_memory(files, tmp_path: Path, no_disk) -> None:
	inner = write_zip(tmp_path / "interne.zip", {"a.txt": b"A" * 2_000_000})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w", zipfile.ZIP_STORED) as handle:
		handle.writestr("notes.txt", inner.read_bytes())
	verdict = Scanner().inspect(RemoteSource(files.add("externe.zip", outer.read_bytes())))
	assert verdict.safe is False
	assert verdict.codes == ["nested"]
	assert verdict.children[0].codes == ["ratio"]


def test_a_nested_archive_beyond_the_memory_buffer_is_refused(
	files, tmp_path: Path, no_disk
) -> None:
	inner = write_zip(tmp_path / "interne.zip", {"a.bin": os.urandom(200_000)})
	outer = tmp_path / "externe.zip"
	with zipfile.ZipFile(outer, "w", zipfile.ZIP_STORED) as handle:
		handle.writestr("interne.zip", inner.read_bytes())
	scanner = Scanner(Limits(max_buffer_bytes=50_000))
	verdict = scanner.inspect(RemoteSource(files.add("externe.zip", outer.read_bytes())))
	assert verdict.safe is False
	assert verdict.children[0].codes == ["nested_cut"]


def test_a_remote_tar_gz_streams_without_ranges(files, tmp_path: Path, no_disk) -> None:
	files.ranges = False
	archive = write_tar(tmp_path / "ok.tar.gz", {"a.txt": b"bonjour"})
	source = RemoteSource(files.add("ok.tar.gz", archive.read_bytes()))
	verdict = Scanner().inspect(source)
	assert source.seekable is False
	assert verdict.safe is True
	assert verdict.stats["kind"] == "tar.gz"


def test_a_remote_tar_gz_bomb_is_cut(files, tmp_path: Path, no_disk) -> None:
	archive = tmp_path / "bombe.tar.gz"
	with tarfile.open(archive, "w:gz") as handle:
		info = tarfile.TarInfo("a.txt")
		info.size = 3_000_000
		handle.addfile(info, io.BytesIO(b"\0" * info.size))
	verdict = Scanner(Limits(max_total_bytes=1_000_000)).inspect(
		RemoteSource(files.add("bombe.tar.gz", archive.read_bytes()))
	)
	assert verdict.codes == ["read_cap"]


def test_a_zip_without_ranges_is_refused_with_a_clear_reason(files, tmp_path: Path) -> None:
	files.ranges = False
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	verdict = Scanner().inspect(RemoteSource(files.add("ok.zip", archive.read_bytes())))
	assert verdict.safe is False
	assert verdict.codes == ["unsupported"]
	assert "plages" in verdict.reasons[0]


def test_the_download_cap_is_the_reason_given(files, tmp_path: Path, no_disk) -> None:
	files.ranges = False
	noise = os.urandom(500_000)
	archive = write_tar(tmp_path / "gros.tar.gz", {"a.bin": noise})
	source = RemoteSource(files.add("gros.tar.gz", archive.read_bytes()), max_download_bytes=100_000)
	verdict = Scanner(Limits(max_download_bytes=100_000)).inspect(source)
	assert verdict.safe is False
	assert verdict.codes[0] == "download_cap"
	assert source.cap_exceeded is True


def test_a_server_without_content_length_is_refused(files, tmp_path: Path) -> None:
	files.ranges = False
	files.announce_length = False
	archive = write_tar(tmp_path / "ok.tar.gz", {"a.txt": b"bonjour"})
	with pytest.raises(RemoteError, match="taille"):
		RemoteSource(files.add("ok.tar.gz", archive.read_bytes()))


def test_a_recompressing_server_is_refused(files, tmp_path: Path) -> None:
	files.encoding = "gzip"
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	with pytest.raises(RemoteError, match="recompresse"):
		RemoteSource(files.add("ok.zip", archive.read_bytes()))


def test_a_missing_remote_file_is_an_error(files) -> None:
	with pytest.raises(RemoteError, match="404"):
		RemoteSource(files.add("x", b"").rsplit("/", 1)[0] + "/absent.zip")


@pytest.mark.parametrize("url", ["ftp://exemple.org/a.zip", "file:///etc/passwd", "http://"])
def test_only_http_urls_are_accepted(url: str) -> None:
	with pytest.raises(ValueError):
		RemoteSource(url)


def test_a_remote_archive_can_be_trusted(files, tmp_path: Path) -> None:
	from zipguard.trust import fingerprint

	archive = write_zip(tmp_path / "bombe.zip", {"a.txt": b"A" * 2_000_000})
	url = files.add("bombe.zip", archive.read_bytes())
	verdict = Scanner(trusted={fingerprint(archive)}).inspect(RemoteSource(url))
	assert verdict.safe is True
	assert verdict.stats["trusted"] is True


def test_the_cli_scans_a_url(files, tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	url = files.add("ok.zip", archive.read_bytes())
	assert main(["scan", url, "--json"]) == EXIT_OK
	payload = json.loads(capsys.readouterr().out)
	assert payload["archive"] == url
	assert payload["stats"]["downloaded_bytes"] > 0


def test_the_cli_refuses_a_remote_bomb(files, tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "bombe.zip", {"a.txt": b"A" * 2_000_000})
	assert main(["scan", files.add("bombe.zip", archive.read_bytes()), "--no-color"]) == EXIT_UNSAFE
	assert "téléchargé" in capsys.readouterr().out


def test_the_cli_reports_an_unreachable_url(files, capsys) -> None:
	url = files.add("x", b"").rsplit("/", 1)[0] + "/absent.zip"
	assert main(["scan", url]) == EXIT_ERROR
	assert "injoignable" in capsys.readouterr().err


py7zr = pytest.importorskip("py7zr", reason="L'extra 7z n'est pas installé.")


def test_a_remote_seven_zip_is_inspected_in_memory(files, tmp_path: Path, no_disk) -> None:
	inner = write_zip(tmp_path / "interne.zip", {"a.txt": b"A" * 2_000_000})
	archive = tmp_path / "externe.7z"
	with py7zr.SevenZipFile(archive, "w") as handle:
		handle.writestr(inner.read_bytes(), "notes.txt")
	verdict = Scanner().inspect(RemoteSource(files.add("externe.7z", archive.read_bytes())))
	assert verdict.safe is False
	assert verdict.codes == ["nested"]


def test_a_redirect_to_ftp_is_refused(files) -> None:
	files.redirect_to = "ftp://exemple.org/a.zip"
	with pytest.raises(RemoteError, match="Redirection refusée"):
		RemoteSource(files.add("a.zip", b"PK"))


def test_a_file_changed_during_inspection_is_not_judged(files, tmp_path: Path) -> None:
	first = write_zip(tmp_path / "v1.zip", {"a.txt": b"bonjour", "b.bin": os.urandom(300_000)})
	files.etags["a.zip"] = '"v1"'
	source = RemoteSource(files.add("a.zip", first.read_bytes()))
	second = write_zip(tmp_path / "v2.zip", {"a.txt": b"A" * 2_000_000})
	files.blobs["a.zip"] = second.read_bytes()
	files.etags["a.zip"] = '"v2"'
	verdict = Scanner().inspect(source)
	assert verdict.safe is False
	assert "changé" in " ".join(verdict.reasons)


def test_an_unchanged_file_keeps_its_validator(files, tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	files.etags["ok.zip"] = '"stable"'
	assert Scanner().inspect(RemoteSource(files.add("ok.zip", archive.read_bytes()))).safe is True


def test_the_total_deadline_is_the_reason_given(files, tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	source = RemoteSource(files.add("ok.zip", archive.read_bytes()), deadline=5.0)
	source._started -= 10  # le délai total est écoulé juste après la première requête
	verdict = Scanner().inspect(source)
	assert verdict.safe is False
	assert verdict.codes[0] == "download_timeout"


def test_credentials_never_reach_the_report(files, tmp_path: Path, capsys) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	url = files.add("ok.zip", archive.read_bytes()).replace("http://", "http://moi:secret@")
	assert main(["scan", url, "--json"]) == EXIT_OK
	output = capsys.readouterr().out
	assert "secret" not in output
	assert "***@" in json.loads(output)["archive"]
	assert set(files.authorizations) == {"Basic bW9pOnNlY3JldA=="}  # moi:secret


def test_a_remote_seven_zip_entry_beyond_the_buffer_is_unverifiable(
	files, tmp_path: Path, no_disk
) -> None:
	archive = tmp_path / "gros.7z"
	with py7zr.SevenZipFile(archive, "w") as handle:
		handle.writestr(os.urandom(200_000), "bruit.bin")
	scanner = Scanner(Limits(max_buffer_bytes=50_000))
	verdict = scanner.inspect(RemoteSource(files.add("gros.7z", archive.read_bytes())))
	assert verdict.safe is False
	assert "nested_cut" in verdict.codes


def test_credentials_are_not_forwarded_on_redirect(files, tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	target = files.add("cible.zip", archive.read_bytes())
	files.redirects["depart.zip"] = target
	url = target.rsplit("/", 1)[0].replace("http://", "http://moi:secret@") + "/depart.zip"
	verdict = Scanner().inspect(RemoteSource(url))
	assert verdict.safe is True
	assert files.authorizations[0] is not None
	assert all(header is None for header in files.authorizations[1::2])
