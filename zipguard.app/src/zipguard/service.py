from __future__ import annotations

import json
import multiprocessing
import shutil
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .limits import Limits, Verdict
from .report import SCHEMA_VERSION
from .scanner import Scanner

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8723
DEFAULT_MAX_UPLOAD_BYTES = 64_000_000
DEFAULT_TIMEOUT = 30.0


class ScanTimeout(Exception):
	"""
	Description: Signale qu'une analyse a dépassé son délai et que le worker a été tué.
	Usage: levée par scan_in_worker quand le délai est écoulé.
	Inputs: message (str) délai dépassé.
	Outputs: exception à traduire en réponse 504 par le serveur.
	"""


def _worker(path: str, limits: dict, pipe) -> None:
	"""
	Description: Analyse une archive dans un processus séparé et renvoie le verdict par le tube.
	Usage: cible interne de multiprocessing, jamais appelée directement.
	Inputs: path (str) archive, limits (dict) seuils sérialisés, pipe (Connection) tube de retour.
	Outputs: None, le verdict part dans le tube.

	Doit rester au niveau du module pour être picklable avec la méthode spawn.
	"""

	try:
		verdict = Scanner(Limits(**limits)).inspect(Path(path))
		pipe.send(("ok", verdict.as_dict()))
	except BaseException as error:  # pragma: no cover - filet de sécurité du worker
		pipe.send(("error", f"{type(error).__name__}: {error}"))
	finally:
		pipe.close()


def _verdict_from_dict(payload: dict) -> Verdict:
	"""
	Description: Reconstruit un Verdict depuis sa forme sérialisée, enfants compris.
	Usage: _verdict_from_dict(payload).
	Inputs: payload (dict) verdict sérialisé par Verdict.as_dict.
	Outputs: Verdict équivalent.
	"""

	return Verdict(
		safe=payload["safe"],
		reasons=list(payload["reasons"]),
		stats=dict(payload["stats"]),
		children=[_verdict_from_dict(child) for child in payload.get("children", [])],
	)


def scan_in_worker(path: Path, limits: Limits, timeout: float = DEFAULT_TIMEOUT) -> Verdict:
	"""
	Description: Analyse une archive dans un processus jetable, tué net au bout du délai.
	Usage: scan_in_worker(Path("suspect.zip"), Limits(), timeout=30).
	Inputs: path (Path) archive, limits (Limits) seuils, timeout (float) délai en secondes.
	Outputs: Verdict de l'analyse.

	Un serveur qui analyse des archives inconnues dans son propre processus se fait tuer
	par la première qui épuise la mémoire ou tourne trop longtemps. Le travail part donc
	dans un processus séparé dont le serveur peut se débarrasser, ce qui plafonne le dégât
	d'une archive pathologique à un worker perdu.
	"""

	context = multiprocessing.get_context("spawn")
	parent, child = context.Pipe(duplex=False)
	process = context.Process(target=_worker, args=(str(path), limits.as_dict(), child))
	process.start()
	child.close()

	try:
		process.join(timeout)
		if process.is_alive():
			process.terminate()
			process.join(5)
			raise ScanTimeout(f"Analyse interrompue après {timeout} s.")

		if not parent.poll():
			raise ScanTimeout("Le worker s'est arrêté sans rendre de verdict.")

		status, payload = parent.recv()
		if status == "error":  # pragma: no cover - dépend d'une panne du worker
			raise RuntimeError(payload)
		return _verdict_from_dict(payload)
	finally:
		parent.close()
		if process.is_alive():  # pragma: no cover - nettoyage best effort
			process.kill()


class _Handler(BaseHTTPRequestHandler):
	"""
	Description: Routes HTTP du mode service : santé, seuils, et analyse d'un envoi.
	Usage: instancié par build_server, jamais à la main.
	Inputs: requêtes HTTP ; la configuration vient des attributs de classe posés par build_server.
	Outputs: réponses JSON.
	"""

	server_version = "ZipGuard"
	sys_version = ""

	limits: Limits = Limits()
	max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
	timeout_seconds: float = DEFAULT_TIMEOUT
	isolate: bool = True
	quiet: bool = True

	def log_message(self, fmt: str, *args) -> None:
		if not self.quiet:  # pragma: no cover - dépend du mode verbeux
			super().log_message(fmt, *args)

	def _send(self, code: int, payload: dict) -> None:
		body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
		self.send_response(code)
		self.send_header("Content-Type", "application/json; charset=utf-8")
		self.send_header("Content-Length", str(len(body)))
		self.send_header("X-Content-Type-Options", "nosniff")
		self.end_headers()
		self.wfile.write(body)

	def do_GET(self) -> None:
		from . import __version__

		if self.path == "/health":
			self._send(200, {"status": "ok", "version": __version__})
		elif self.path == "/limits":
			self._send(200, self.limits.as_dict())
		else:
			self._send(404, {"error": "Route inconnue.", "routes": ["/health", "/limits", "/scan"]})

	def do_POST(self) -> None:
		if self.path != "/scan":
			self._send(405, {"error": "Cette route ne répond qu'en GET."})
			return

		try:
			length = int(self.headers.get("Content-Length", "0"))
		except ValueError:
			self._send(400, {"error": "En tête Content-Length illisible."})
			return

		if length <= 0:
			self._send(400, {"error": "Corps de requête vide : envoie l'archive en octets bruts."})
			return

		if length > self.max_upload_bytes:
			self._send(
				413,
				{
					"error": "Envoi trop volumineux.",
					"max_upload_bytes": self.max_upload_bytes,
					"received_bytes": length,
				},
			)
			return

		self._scan_upload(length)

	def _scan_upload(self, length: int) -> None:
		"""
		Description: Écrit l'envoi dans un dossier temporaire privé, l'analyse, puis l'efface.
		Usage: interne à do_POST.
		Inputs: length (int) taille annoncée du corps.
		Outputs: None, la réponse part par self._send.

		Le fichier reçu ne survit jamais à la requête : on ne garde pas sur disque une
		archive dont on vient justement de dire qu'elle était dangereuse.
		"""

		from . import __version__

		workdir = Path(tempfile.mkdtemp(prefix="zipguard-upload-"))
		target = workdir / "envoi.bin"
		try:
			read = 0
			with open(target, "wb") as sink:
				while read < length:
					chunk = self.rfile.read(min(65536, length - read))
					if not chunk:
						break
					read += len(chunk)
					sink.write(chunk)

			if read == 0:
				self._send(400, {"error": "Corps de requête vide."})
				return

			try:
				if self.isolate:
					verdict = scan_in_worker(target, self.limits, self.timeout_seconds)
				else:
					verdict = Scanner(self.limits).inspect(target)
			except ScanTimeout as error:
				self._send(504, {"error": str(error)})
				return

			self._send(
				200,
				{
					"schema_version": SCHEMA_VERSION,
					"tool": "zipguard",
					"version": __version__,
					"archive": "envoi",
					**verdict.as_dict(),
				},
			)
		finally:
			shutil.rmtree(workdir, ignore_errors=True)


def build_server(
	limits: Limits | None = None,
	host: str = DEFAULT_HOST,
	port: int = DEFAULT_PORT,
	max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
	timeout: float = DEFAULT_TIMEOUT,
	isolate: bool = True,
	quiet: bool = True,
) -> ThreadingHTTPServer:
	"""
	Description: Construit le serveur d'analyse sans le démarrer.
	Usage: build_server(Limits(), port=8723).serve_forever().
	Inputs: limits (Limits) seuils, host (str) interface, port (int) port, max_upload_bytes (int) plafond d'envoi, timeout (float) délai du worker, isolate (bool) analyse en processus séparé, quiet (bool) journal muet.
	Outputs: ThreadingHTTPServer prêt à servir.

	L'écoute est volontairement sur la boucle locale par défaut : un service qui déballe des
	archives inconnues ne s'expose pas au réseau sans que quelqu'un l'ait décidé.
	"""

	handler = type(
		"_ConfiguredHandler",
		(_Handler,),
		{
			"limits": limits or Limits(),
			"max_upload_bytes": max_upload_bytes,
			"timeout_seconds": timeout,
			"isolate": isolate,
			"quiet": quiet,
		},
	)
	return ThreadingHTTPServer((host, port), handler)


def serve(
	limits: Limits | None = None,
	host: str = DEFAULT_HOST,
	port: int = DEFAULT_PORT,
	max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
	timeout: float = DEFAULT_TIMEOUT,
	isolate: bool = True,
) -> None:
	"""
	Description: Démarre le serveur et sert jusqu'à l'interruption au clavier.
	Usage: serve(Limits(), port=8723).
	Inputs: identiques à build_server.
	Outputs: None.
	"""

	httpd = build_server(limits, host, port, max_upload_bytes, timeout, isolate, quiet=False)
	bound_host, bound_port = httpd.server_address[0], httpd.server_address[1]
	print(f"ZipGuard écoute sur http://{bound_host}:{bound_port}")
	print("  GET  /health   état du service")
	print("  GET  /limits   seuils appliqués")
	print("  POST /scan     archive en octets bruts, verdict en JSON")
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		print("\nArrêt demandé.")
	finally:
		httpd.shutdown()
		httpd.server_close()
