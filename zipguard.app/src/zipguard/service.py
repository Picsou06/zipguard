from __future__ import annotations

import json
import multiprocessing
import shutil
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .limits import Limits, Verdict
from .report import SCHEMA_VERSION
from .scanner import Scanner

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8723
DEFAULT_MAX_UPLOAD_BYTES = 64_000_000
DEFAULT_TIMEOUT = 30.0
DEFAULT_READ_TIMEOUT = 30.0
DEFAULT_MAX_CONCURRENT = 4
DEFAULT_MAX_MEMORY_BYTES = 1_000_000_000


class ScanTimeout(Exception):
	"""
	Description: Signale qu'une analyse a dépassé son délai et que le worker a été tué.
	Usage: levée par scan_in_worker quand le délai est écoulé.
	Inputs: message (str) délai dépassé.
	Outputs: exception à traduire en réponse 504 par le serveur.
	"""


class WorkerFailed(RuntimeError):
	"""
	Description: Signale qu'un worker est mort ou a planté sans rendre de verdict exploitable.
	Usage: levée par scan_in_worker ; le serveur la traduit en réponse 500.
	Inputs: message (str) cause connue.
	Outputs: exception dérivant de RuntimeError.
	"""


def apply_memory_limit(max_bytes: int) -> bool:
	"""
	Description: Plafonne l'espace d'adressage du processus courant, là où le système le permet.
	Usage: appelée en tête du worker, jamais dans le serveur lui même.
	Inputs: max_bytes (int) plafond en octets, 0 pour ne rien limiter.
	Outputs: bool vrai si le plafond a été posé.

	Le délai coupe une analyse trop longue, pas une analyse trop gourmande : sans plafond,
	une archive qui fait gonfler la mémoire peut faire tuer bien plus que son worker par le
	système. Avec, l'allocation fautive échoue en MemoryError dans le worker seul.
	"""

	if max_bytes <= 0:
		return False
	try:
		import resource
	except ImportError:  # pragma: no cover - Windows n'a pas de module resource
		return False
	try:
		_, hard = resource.getrlimit(resource.RLIMIT_AS)
		ceiling = max_bytes if hard == resource.RLIM_INFINITY else min(max_bytes, hard)
		resource.setrlimit(resource.RLIMIT_AS, (ceiling, hard))
	except (ValueError, OSError):  # pragma: no cover - dépend du système
		return False
	return True


def _worker(path: str, limits: dict, pipe, max_memory_bytes: int = 0) -> None:
	"""
	Description: Analyse une archive dans un processus séparé et renvoie le verdict par le tube.
	Usage: cible interne de multiprocessing, jamais appelée directement.
	Inputs: path (str) archive, limits (dict) seuils sérialisés, pipe (Connection) tube de retour, max_memory_bytes (int) plafond mémoire, 0 pour aucun.
	Outputs: None, le verdict part dans le tube.

	Doit rester au niveau du module pour être picklable avec la méthode spawn. Une archive
	qui épuise la mémoire autorisée est un signal en soi : elle reçoit un verdict dangereux
	plutôt qu'une erreur.
	"""

	try:
		apply_memory_limit(max_memory_bytes)
		try:
			verdict = Scanner(Limits(**limits)).inspect(Path(path))
		except MemoryError:
			verdict = Verdict(
				False,
				["Mémoire épuisée pendant l'analyse : l'archive dépasse le plafond du worker."],
				{"name": Path(path).name, "depth": 0},
			)
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


def scan_in_worker(
	path: Path,
	limits: Limits,
	timeout: float = DEFAULT_TIMEOUT,
	max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES,
) -> Verdict:
	"""
	Description: Analyse une archive dans un processus jetable, tué net au bout du délai.
	Usage: scan_in_worker(Path("suspect.zip"), Limits(), timeout=30).
	Inputs: path (Path) archive, limits (Limits) seuils, timeout (float) délai en secondes, max_memory_bytes (int) plafond mémoire du worker, 0 pour aucun.
	Outputs: Verdict de l'analyse.

	Un serveur qui analyse des archives inconnues dans son propre processus se fait tuer
	par la première qui épuise la mémoire ou tourne trop longtemps. Le travail part donc
	dans un processus séparé dont le serveur peut se débarrasser, ce qui plafonne le dégât
	d'une archive pathologique à un worker perdu.
	"""

	context = multiprocessing.get_context("spawn")
	parent, child = context.Pipe(duplex=False)
	process = context.Process(
		target=_worker,
		args=(str(path), limits.as_dict(), child, max_memory_bytes),
	)
	process.start()
	child.close()

	try:
		process.join(timeout)
		if process.is_alive():
			process.terminate()
			process.join(5)
			raise ScanTimeout(f"Analyse interrompue après {timeout} s.")

		if not parent.poll():
			raise WorkerFailed(f"Le worker s'est arrêté sans rendre de verdict (code {process.exitcode}).")

		status, payload = parent.recv()
		if status == "error":  # pragma: no cover - dépend d'une panne du worker
			raise WorkerFailed(payload)
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
	max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES
	isolate: bool = True
	quiet: bool = True

	# Délai appliqué à chaque lecture sur la socket : un client qui envoie son corps un
	# octet à la fois (slowloris) ne garde plus un thread pour toujours.
	timeout: float | None = DEFAULT_READ_TIMEOUT

	# Nombre d'envois traités en même temps, réception comprise. Sans lui, cent requêtes
	# simultanées lanceraient cent workers et écriraient cent envois sur le disque.
	slots: threading.BoundedSemaphore = threading.BoundedSemaphore(DEFAULT_MAX_CONCURRENT)

	def log_message(self, fmt: str, *args) -> None:
		if not self.quiet:  # pragma: no cover - dépend du mode verbeux
			super().log_message(fmt, *args)

	def _send(self, code: int, payload: dict, headers: dict[str, str] | None = None) -> None:
		body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
		self.send_response(code)
		self.send_header("Content-Type", "application/json; charset=utf-8")
		self.send_header("Content-Length", str(len(body)))
		self.send_header("X-Content-Type-Options", "nosniff")
		if self.close_connection:
			self.send_header("Connection", "close")
		for key, value in (headers or {}).items():
			self.send_header(key, value)
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

		if not self.slots.acquire(blocking=False):
			self.close_connection = True
			self._send(
				503,
				{"error": "Trop d'analyses en cours, réessaie dans un instant."},
				headers={"Retry-After": "2"},
			)
			return
		# Le créneau est rendu avant la réponse : un client qui enchaîne ses envois ne doit
		# pas recevoir un 503 parce que son propre envoi précédent n'était pas encore libéré.
		try:
			code, payload = self._scan_upload(length)
		finally:
			self.slots.release()
		self._send(code, payload)

	def _scan_upload(self, length: int) -> tuple[int, dict]:
		"""
		Description: Écrit l'envoi dans un dossier temporaire privé, l'analyse, puis l'efface.
		Usage: interne à do_POST.
		Inputs: length (int) taille annoncée du corps.
		Outputs: tuple[int, dict] code HTTP et corps JSON de la réponse.

		Le fichier reçu ne survit jamais à la requête : on ne garde pas sur disque une
		archive dont on vient justement de dire qu'elle était dangereuse.
		"""

		from . import __version__

		workdir = Path(tempfile.mkdtemp(prefix="zipguard-upload-"))
		target = workdir / "envoi.bin"
		try:
			read = 0
			try:
				with open(target, "wb") as sink:
					while read < length:
						chunk = self.rfile.read(min(65536, length - read))
						if not chunk:
							break
						read += len(chunk)
						sink.write(chunk)
			except TimeoutError:
				self.close_connection = True
				return 408, {"error": "Envoi trop lent : délai de réception dépassé."}

			if read < length:
				self.close_connection = True
				return 400, {"error": "Corps tronqué.", "expected_bytes": length, "received_bytes": read}

			try:
				if self.isolate:
					verdict = scan_in_worker(target, self.limits, self.timeout_seconds, self.max_memory_bytes)
				else:
					verdict = Scanner(self.limits).inspect(target)
			except ScanTimeout as error:
				return 504, {"error": str(error)}
			except WorkerFailed as error:
				return 500, {"error": str(error)}

			return 200, {
				"schema_version": SCHEMA_VERSION,
				"tool": "zipguard",
				"version": __version__,
				"archive": "envoi",
				**verdict.as_dict(),
			}
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
	read_timeout: float = DEFAULT_READ_TIMEOUT,
	max_concurrent: int = DEFAULT_MAX_CONCURRENT,
	max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES,
) -> ThreadingHTTPServer:
	"""
	Description: Construit le serveur d'analyse sans le démarrer.
	Usage: build_server(Limits(), port=8723).serve_forever().
	Inputs: limits (Limits) seuils, host (str) interface, port (int) port, max_upload_bytes (int) plafond d'envoi, timeout (float) délai du worker, isolate (bool) analyse en processus séparé, quiet (bool) journal muet, read_timeout (float) délai de chaque lecture réseau, max_concurrent (int) envois traités en même temps, max_memory_bytes (int) plafond mémoire du worker, 0 pour aucun.
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
			"timeout": read_timeout,
			"slots": threading.BoundedSemaphore(max(1, max_concurrent)),
			"max_memory_bytes": max_memory_bytes,
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
	read_timeout: float = DEFAULT_READ_TIMEOUT,
	max_concurrent: int = DEFAULT_MAX_CONCURRENT,
	max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES,
) -> None:
	"""
	Description: Démarre le serveur et sert jusqu'à l'interruption au clavier.
	Usage: serve(Limits(), port=8723).
	Inputs: identiques à build_server.
	Outputs: None.
	"""

	httpd = build_server(
		limits,
		host,
		port,
		max_upload_bytes,
		timeout,
		isolate,
		quiet=False,
		read_timeout=read_timeout,
		max_concurrent=max_concurrent,
		max_memory_bytes=max_memory_bytes,
	)
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
