from __future__ import annotations

import json
import math
import multiprocessing
import shutil
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .limits import Limits, Verdict
from .report import SCHEMA_VERSION
from .sandbox import (
	CgroupJail,
	SandboxConfig,
	apply_memory_limit,
	apply_sandbox,
	seccomp_supported,
)
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


def _worker(
	path: str,
	limits: dict,
	pipe,
	max_memory_bytes: int = 0,
	trusted: tuple[str, ...] = (),
	sandbox: dict | None = None,
	cgroup: str | None = None,
) -> None:
	"""
	Description: Analyse une archive dans un processus séparé et renvoie le verdict par le tube.
	Usage: cible interne de multiprocessing, jamais appelée directement.
	Inputs: path (str) archive, limits (dict) seuils sérialisés, pipe (Connection) tube de retour, max_memory_bytes (int) plafond mémoire sans bac à sable, trusted (tuple[str, ...]) empreintes de confiance, sandbox (dict | None) SandboxConfig sérialisée, cgroup (str | None) cgroup à rejoindre.
	Outputs: None, le verdict et le rapport du bac à sable partent dans le tube.

	Doit rester au niveau du module pour être picklable avec la méthode spawn. Le bac à
	sable est posé avant que le moindre octet de l'archive soit lu. Une archive qui épuise
	la mémoire autorisée est un signal en soi : elle reçoit un verdict dangereux plutôt
	qu'une erreur.
	"""

	try:
		if sandbox is not None:
			report = apply_sandbox(SandboxConfig(**sandbox), cgroup)
		else:
			report = {"mode": "memory", "rlimits": {"memory": apply_memory_limit(max_memory_bytes)}}
		try:
			verdict = Scanner(Limits(**limits), trusted=trusted).inspect(Path(path))
		except MemoryError:
			verdict = Verdict.refused(
				{"name": Path(path).name, "depth": 0},
				"memory",
				"Mémoire épuisée pendant l'analyse : l'archive dépasse le plafond du worker.",
			)
		pipe.send(("ok", verdict.as_dict(), report))
	except BaseException as error:  # pragma: no cover - filet de sécurité du worker
		pipe.send(("error", f"{type(error).__name__}: {error}", {}))
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
		codes=list(payload.get("codes", [])),
	)


def scan_in_worker(
	path: Path,
	limits: Limits,
	timeout: float = DEFAULT_TIMEOUT,
	max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES,
	trusted: frozenset[str] = frozenset(),
	sandbox: SandboxConfig | None = None,
) -> Verdict:
	"""
	Description: Analyse une archive dans un processus jetable, tué net au bout du délai.
	Usage: scan_in_worker(Path("suspect.zip"), Limits(), timeout=30).
	Inputs: identiques à scan_in_worker_report.
	Outputs: Verdict de l'analyse.
	"""

	verdict, _ = scan_in_worker_report(path, limits, timeout, max_memory_bytes, trusted, sandbox)
	return verdict


def scan_in_worker_report(
	path: Path,
	limits: Limits,
	timeout: float = DEFAULT_TIMEOUT,
	max_memory_bytes: int = DEFAULT_MAX_MEMORY_BYTES,
	trusted: frozenset[str] = frozenset(),
	sandbox: SandboxConfig | None = None,
) -> tuple[Verdict, dict]:
	"""
	Description: Analyse une archive dans un processus jetable et rapporte le bac à sable posé.
	Usage: verdict, report = scan_in_worker_report(Path("a.zip"), Limits(), sandbox=SandboxConfig()).
	Inputs: path (Path) archive, limits (Limits) seuils, timeout (float) délai en secondes, max_memory_bytes (int) plafond mémoire quand sandbox est None, trusted (frozenset[str]) empreintes de confiance, sandbox (SandboxConfig | None) bac à sable complet.
	Outputs: tuple (Verdict, dict décrivant le bac à sable réellement en place).

	Un serveur qui analyse des archives inconnues dans son propre processus se fait tuer
	par la première qui épuise la mémoire ou tourne trop longtemps. Le travail part donc
	dans un processus séparé dont le serveur peut se débarrasser, ce qui plafonne le dégât
	d'une archive pathologique à un worker perdu.

	Le tube est lu avant d'attendre la fin du worker : un verdict plus gros que le tampon du
	tube bloquerait sinon le worker sur son écriture, et l'analyse passerait à tort pour un
	délai dépassé.
	"""

	jail, jail_error = _open_jail(sandbox)
	context = multiprocessing.get_context("spawn")
	parent, child = context.Pipe(duplex=False)
	process = context.Process(
		target=_worker,
		args=(
			str(path),
			limits.as_dict(),
			child,
			max_memory_bytes,
			tuple(sorted(trusted)),
			None if sandbox is None else sandbox.as_dict(),
			None if jail is None else str(jail.path),
		),
	)
	process.start()
	child.close()

	try:
		if not parent.poll(timeout):
			if jail is not None:
				jail.kill()
			process.terminate()
			process.join(5)
			raise ScanTimeout(f"Analyse interrompue après {timeout} s.")

		try:
			status, payload, report = parent.recv()
		except EOFError as error:
			process.join(5)
			raise WorkerFailed(
				f"Le worker s'est arrêté sans rendre de verdict (code {process.exitcode})."
			) from error
		process.join(5)

		if status == "error":
			raise WorkerFailed(payload)
		if jail_error is not None:
			report = {**report, "cgroup": False, "cgroup_error": jail_error}
		return _verdict_from_dict(payload), report
	finally:
		parent.close()
		if process.is_alive():  # pragma: no cover - nettoyage best effort
			process.kill()
			process.join(5)
		if jail is not None:
			jail.remove()


def _open_jail(sandbox: SandboxConfig | None) -> tuple[CgroupJail | None, str | None]:
	"""
	Description: Crée le cgroup du prochain worker, si la configuration en demande un.
	Usage: interne à scan_in_worker_report.
	Inputs: sandbox (SandboxConfig | None).
	Outputs: tuple (cgroup créé ou None, raison de l'échec ou None).

	En mode strict, un cgroup impossible à créer arrête l'analyse avant qu'elle commence.
	"""

	if sandbox is None or sandbox.mode == "off" or not sandbox.cgroup_root:
		return None, None
	try:
		return CgroupJail(Path(sandbox.cgroup_root), sandbox.max_memory_bytes, sandbox.pids_max), None
	except OSError as error:
		if sandbox.mode == "strict":
			raise WorkerFailed(f"Bac à sable incomplet en mode strict : cgroup ({error}).") from error
		return None, str(error)


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
	trusted: frozenset[str] = frozenset()
	sandbox: SandboxConfig | None = None
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
			self._send(200, {"status": "ok", "version": __version__, "sandbox": self._sandbox_summary()})
		elif self.path == "/limits":
			self._send(200, {**self.limits.as_dict(), "trusted_fingerprints": len(self.trusted)})
		else:
			self._send(404, {"error": "Route inconnue.", "routes": ["/health", "/limits", "/scan"]})

	def _sandbox_summary(self) -> dict:
		"""
		Description: Décrit le bac à sable configuré, pour /health.
		Usage: interne.
		Inputs: aucun.
		Outputs: dict mode, seccomp disponible, cgroup délégué.
		"""

		if not self.isolate:
			return {"mode": "aucun", "detail": "analyse dans le processus du serveur (--no-isolate)"}
		if self.sandbox is None:
			return {"mode": "memory"}
		return {
			"mode": self.sandbox.mode,
			"seccomp_supported": seccomp_supported(),
			"cgroup_root": self.sandbox.cgroup_root,
		}

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

			extra: dict = {}
			try:
				if self.isolate:
					verdict, extra["sandbox"] = scan_in_worker_report(
						target,
						self.limits,
						self.timeout_seconds,
						self.max_memory_bytes,
						self.trusted,
						self.sandbox,
					)
				else:
					verdict = Scanner(self.limits, trusted=self.trusted).inspect(target)
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
				**extra,
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
	trusted: frozenset[str] = frozenset(),
	sandbox: str = "auto",
	cgroup_root: str | None = None,
) -> ThreadingHTTPServer:
	"""
	Description: Construit le serveur d'analyse sans le démarrer.
	Usage: build_server(Limits(), port=8723).serve_forever().
	Inputs: limits (Limits) seuils, host (str) interface, port (int) port, max_upload_bytes (int) plafond d'envoi, timeout (float) délai du worker, isolate (bool) analyse en processus séparé, quiet (bool) journal muet, read_timeout (float) délai de chaque lecture réseau, max_concurrent (int) envois traités en même temps, max_memory_bytes (int) plafond mémoire du worker, 0 pour aucun, trusted (frozenset[str]) empreintes de confiance, sandbox (str) auto, strict ou off, cgroup_root (str | None) cgroup v2 délégué.
	Outputs: ThreadingHTTPServer prêt à servir.

	L'écoute est volontairement sur la boucle locale par défaut : un service qui déballe des
	archives inconnues ne s'expose pas au réseau sans que quelqu'un l'ait décidé.
	"""

	limits = limits or Limits()
	sandbox_config = SandboxConfig(
		mode=sandbox,
		max_memory_bytes=max_memory_bytes,
		# Le délai mur reste le garde fou principal ; le plafond de temps processeur rattrape
		# un worker qui échapperait à terminate, une seconde après.
		cpu_seconds=math.ceil(timeout) + 1 if timeout > 0 else 0,
		# Le worker n'écrit que des copies d'archives imbriquées, plafonnées par ces seuils.
		max_file_bytes=min(limits.max_entry_bytes, limits.max_total_bytes) + 1_000_000,
		cgroup_root=cgroup_root,
	)
	handler = type(
		"_ConfiguredHandler",
		(_Handler,),
		{
			"limits": limits,
			"max_upload_bytes": max_upload_bytes,
			"timeout_seconds": timeout,
			"isolate": isolate,
			"quiet": quiet,
			"timeout": read_timeout,
			"slots": threading.BoundedSemaphore(max(1, max_concurrent)),
			"max_memory_bytes": max_memory_bytes,
			"trusted": frozenset(trusted),
			"sandbox": sandbox_config,
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
	trusted: frozenset[str] = frozenset(),
	sandbox: str = "auto",
	cgroup_root: str | None = None,
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
		trusted=trusted,
		sandbox=sandbox,
		cgroup_root=cgroup_root,
	)
	bound_host, bound_port = httpd.server_address[0], httpd.server_address[1]
	print(f"ZipGuard écoute sur http://{bound_host}:{bound_port}")
	print("  GET  /health   état du service")
	print("  GET  /limits   seuils appliqués")
	print("  POST /scan     archive en octets bruts, verdict en JSON")
	if isolate:
		print(f"  bac à sable    {sandbox}" + (f", cgroup sous {cgroup_root}" if cgroup_root else ""))
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		print("\nArrêt demandé.")
	finally:
		httpd.shutdown()
		httpd.server_close()
