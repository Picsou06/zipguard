from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from . import __version__
from .bench import bench_json, build_corpus, render_bench, run_bench
from .demo import FORMATS, build_demo_archive
from .formats import detect_kind, supported_kinds
from .limits import Limits, Verdict, human_bytes
from .remote import RemoteSource, is_url
from .report import render, render_json
from .sarif import render_sarif
from .scanner import ExtractionRefused, QuotaExceeded, Scanner
from .trust import fingerprint, load_allowlist

EXIT_OK = 0
EXIT_UNSAFE = 1
EXIT_USAGE = 2
EXIT_ERROR = 3

EPILOGUE = f"""codes de sortie :
  {EXIT_OK}  opération réussie, archive jugée sûre
  {EXIT_UNSAFE}  archive jugée dangereuse, ou extraction refusée
  {EXIT_USAGE}  erreur d'utilisation de la ligne de commande
  {EXIT_ERROR}  erreur d'exécution (fichier introuvable, illisible, plafond de démo)
"""


def _add_threshold_flags(parser: argparse.ArgumentParser) -> None:
	"""
	Description: Ajoute à une sous commande les options qui règlent les seuils de sécurité.
	Usage: _add_threshold_flags(scan_parser).
	Inputs: parser (ArgumentParser) sous commande à enrichir.
	Outputs: None, le parser est modifié sur place.
	"""

	defaults = Limits()
	parser.add_argument("--max-ratio", type=float, default=defaults.max_ratio)
	parser.add_argument("--max-total-mb", type=int, default=defaults.max_total_bytes // 1_000_000)
	parser.add_argument("--max-entry-mb", type=int, default=defaults.max_entry_bytes // 1_000_000)
	parser.add_argument("--max-entries", type=int, default=defaults.max_entries)
	parser.add_argument("--max-depth", type=int, default=defaults.max_depth)


def _add_trust_flag(parser: argparse.ArgumentParser) -> None:
	"""
	Description: Ajoute l'option qui charge une liste d'empreintes de confiance.
	Usage: _add_trust_flag(scan_parser).
	Inputs: parser (ArgumentParser) sous commande à enrichir.
	Outputs: None, le parser est modifié sur place.
	"""

	parser.add_argument(
		"--trust",
		type=Path,
		default=None,
		metavar="FICHIER",
		help="Liste d'empreintes SHA-256 de confiance, au format de sha256sum.",
	)


def _trusted_from(args: argparse.Namespace) -> frozenset[str] | None:
	"""
	Description: Charge la liste de confiance demandée, ou signale pourquoi elle est illisible.
	Usage: trusted = _trusted_from(args).
	Inputs: args (Namespace) options analysées.
	Outputs: frozenset[str] des empreintes, vide sans --trust ; None si le fichier est invalide.
	"""

	if args.trust is None:
		return frozenset()
	try:
		return load_allowlist(args.trust)
	except (OSError, ValueError) as error:
		print(f"zipguard: liste de confiance illisible : {error}", file=sys.stderr)
		return None


def _add_render_flags(parser: argparse.ArgumentParser) -> None:
	"""
	Description: Ajoute les options de mise en forme de la sortie.
	Usage: _add_render_flags(scan_parser).
	Inputs: parser (ArgumentParser) sous commande à enrichir.
	Outputs: None, le parser est modifié sur place.
	"""

	parser.add_argument("--json", action="store_true", help="Sortie JSON au lieu du rapport texte.")
	parser.add_argument("--no-color", action="store_true", help="Désactive les couleurs ANSI.")
	parser.add_argument(
		"--ascii", action="store_true", help="Remplace les pictogrammes par de l'ASCII."
	)


def _limits_from(args: argparse.Namespace) -> Limits:
	"""
	Description: Construit les seuils effectifs à partir des options de la ligne de commande.
	Usage: limits = _limits_from(args).
	Inputs: args (Namespace) options analysées.
	Outputs: Limits immuable.
	"""

	defaults = Limits()
	extract_mb = getattr(args, "max_extract_mb", None)
	free_mb = getattr(args, "min_free_mb", None)
	buffer_mb = getattr(args, "max_buffer_mb", None)
	download_mb = getattr(args, "max_download_mb", None)

	return Limits(
		max_total_bytes=args.max_total_mb * 1_000_000,
		max_entry_bytes=args.max_entry_mb * 1_000_000,
		max_ratio=args.max_ratio,
		max_entries=args.max_entries,
		max_depth=args.max_depth,
		max_extract_bytes=(defaults.max_extract_bytes if extract_mb is None else extract_mb * 1_000_000),
		min_free_bytes=(defaults.min_free_bytes if free_mb is None else free_mb * 1_000_000),
		max_buffer_bytes=(defaults.max_buffer_bytes if buffer_mb is None else buffer_mb * 1_000_000),
		max_download_bytes=(
			defaults.max_download_bytes if download_mb is None else download_mb * 1_000_000
		),
	)


def _render_options(args: argparse.Namespace) -> dict:
	"""
	Description: Traduit les options de mise en forme en arguments pour le moteur de rendu.
	Usage: render(path, verdict, **_render_options(args)).
	Inputs: args (Namespace) options analysées.
	Outputs: dict des arguments nommés color et unicode.
	"""

	return {
		"color": False if args.no_color else None,
		"unicode": False if args.ascii else None,
	}


def _build_parser() -> argparse.ArgumentParser:
	"""
	Description: Construit l'interface en ligne de commande de ZipGuard.
	Usage: parser = _build_parser(); parser.parse_args().
	Inputs: aucun.
	Outputs: ArgumentParser configuré avec toutes les sous commandes.
	"""

	parser = argparse.ArgumentParser(
		prog="zipguard",
		description="Inspecte des archives et illustre les bombes de décompression, sans danger.",
		epilog=EPILOGUE,
		formatter_class=argparse.RawDescriptionHelpFormatter,
	)
	parser.add_argument("--version", action="version", version=f"zipguard {__version__}")
	sub = parser.add_subparsers(dest="command", required=True)

	scan = sub.add_parser(
		"scan",
		help="Inspecte une ou plusieurs archives, ou tout un dossier, et rend un verdict.",
	)
	scan.add_argument(
		"targets",
		nargs="+",
		metavar="ARCHIVE",
		help=(
			"Archive, dossier ou adresse http(s). Un dossier est parcouru et chaque archive "
			"reconnue est inspectée ; une adresse est lue sans rien écrire sur le disque."
		),
	)
	_add_threshold_flags(scan)
	_add_trust_flag(scan)
	_add_render_flags(scan)
	scan.add_argument(
		"--sarif",
		action="store_true",
		help="Sortie SARIF 2.1.0, pour l'onglet Sécurité de GitHub.",
	)
	defaults = Limits()
	scan.add_argument(
		"--max-download-mb",
		type=int,
		default=defaults.max_download_bytes // 1_000_000,
		help="Plafond de téléchargement pour une archive distante.",
	)
	scan.add_argument(
		"--max-buffer-mb",
		type=int,
		default=defaults.max_buffer_bytes // 1_000_000,
		help="Mémoire accordée à chaque archive imbriquée lue sans disque.",
	)
	scan.add_argument(
		"--remote-timeout",
		type=float,
		default=30.0,
		help="Délai de chaque requête vers une archive distante, en secondes.",
	)
	scan.add_argument(
		"--exit-zero",
		action="store_true",
		help="Rend 0 même si une archive est dangereuse (utile pour publier un rapport en CI).",
	)

	extract = sub.add_parser("extract", help="Extrait une archive jugée sûre, en comptant les octets.")
	extract.add_argument("archive", type=Path)
	extract.add_argument("destination", type=Path)
	_add_threshold_flags(extract)
	_add_trust_flag(extract)
	_add_render_flags(extract)
	extract.add_argument("--max-extract-mb", type=int, default=None)
	extract.add_argument("--min-free-mb", type=int, default=None)
	extract.add_argument(
		"--allow-links",
		action="store_true",
		help="Recrée les liens symboliques dont la cible reste sous leur propre dossier.",
	)

	demo = sub.add_parser("demo", help="Crée une archive de démonstration bornée.")
	demo.add_argument("output", type=Path)
	demo.add_argument("--text", default="motif")
	demo.add_argument("--mb", type=int, default=10)
	demo.add_argument("--format", dest="archive_format", choices=FORMATS, default="zip")

	serve = sub.add_parser("serve", help="Expose le scanner en petit service HTTP local.")
	serve.add_argument("--host", default="127.0.0.1")
	serve.add_argument("--port", type=int, default=8723)
	serve.add_argument("--max-upload-mb", type=int, default=64)
	serve.add_argument("--timeout", type=float, default=30.0, help="Délai d'une analyse, en secondes.")
	serve.add_argument(
		"--read-timeout",
		type=float,
		default=30.0,
		help="Délai de chaque lecture réseau, contre les envois au compte goutte.",
	)
	serve.add_argument(
		"--max-concurrent", type=int, default=4, help="Envois traités en même temps, au delà : 503."
	)
	serve.add_argument(
		"--max-memory-mb",
		type=int,
		default=1000,
		help="Plafond mémoire de chaque worker, 0 pour aucun (Linux et macOS).",
	)
	serve.add_argument(
		"--no-isolate",
		action="store_true",
		help="Analyse dans le processus du serveur au lieu d'un worker jetable.",
	)
	_add_threshold_flags(serve)
	_add_trust_flag(serve)

	bench = sub.add_parser("bench", help="Mesure le temps que met chaque garde fou à trancher.")
	bench.add_argument("--repeat", type=int, default=3)
	bench.add_argument("--keep", type=Path, default=None, help="Conserve le corpus dans ce dossier.")
	_add_render_flags(bench)

	sub.add_parser("formats", help="Liste les formats d'archive pris en charge.")

	prints = sub.add_parser(
		"fingerprint",
		help="Affiche l'empreinte SHA-256 d'archives, prête pour une liste --trust.",
	)
	prints.add_argument("archives", type=Path, nargs="+")

	return parser


_SKIPPED_DIRECTORIES = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv"}


def _walk_archives(directory: Path) -> list[Path]:
	"""
	Description: Liste les archives d'un dossier, reconnues par signature.
	Usage: _walk_archives(Path(".")).
	Inputs: directory (Path) dossier à parcourir.
	Outputs: list[Path] triée des fichiers qui sont des archives.

	Les liens symboliques ne sont pas suivis, et les dossiers de gestion de version ou de
	dépendances sont sautés : ils ne contiennent pas d'archives à juger, seulement du bruit
	et du temps perdu.
	"""

	found: list[Path] = []
	for current, dirnames, filenames in os.walk(directory, followlinks=False):
		dirnames[:] = sorted(name for name in dirnames if name not in _SKIPPED_DIRECTORIES)
		for name in sorted(filenames):
			candidate = Path(current) / name
			if candidate.is_symlink() or not candidate.is_file():
				continue
			try:
				if detect_kind(candidate) is not None:
					found.append(candidate)
			except OSError:
				continue
	return found


def _display_path(path: Path) -> str:
	"""
	Description: Chemin affiché et rapporté, relatif au dossier courant quand c'est possible.
	Usage: _display_path(Path("/depot/lib/a.zip")).
	Inputs: path (Path) chemin.
	Outputs: str en séparateurs /, comme l'attend SARIF.
	"""

	try:
		return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
	except ValueError:
		return path.as_posix()


def _collect_targets(
	raw_targets: list[str],
	limits: Limits,
	timeout: float,
) -> list[tuple[str, object]] | None:
	"""
	Description: Transforme les arguments de scan en couples (nom affiché, cible inspectable).
	Usage: targets = _collect_targets(args.targets, limits, 30.0).
	Inputs: raw_targets (list[str]) arguments tels que tapés, limits (Limits) pour le plafond de téléchargement, timeout (float) délai réseau.
	Outputs: list des couples, ou None si un argument n'existe pas ou ne répond pas.
	"""

	targets: list[tuple[str, object]] = []
	for raw in raw_targets:
		if is_url(raw):
			try:
				source = RemoteSource(raw, max_download_bytes=limits.max_download_bytes, timeout=timeout)
			except (OSError, ValueError) as error:
				print(f"zipguard: archive distante injoignable : {raw} ({error})", file=sys.stderr)
				return None
			targets.append((raw, source))
			continue
		path = Path(raw)
		if path.is_dir():
			targets.extend((_display_path(found), found) for found in _walk_archives(path))
		elif path.exists():
			targets.append((raw if not path.is_absolute() else path.as_posix(), path))
		else:
			print(f"zipguard: archive introuvable : {raw}", file=sys.stderr)
			return None
	return targets


def _command_scan(args: argparse.Namespace) -> int:
	"""
	Description: Exécute la sous commande scan.
	Usage: interne à main.
	Inputs: args (Namespace) options analysées.
	Outputs: int code de sortie.

	Avec une seule archive, les sorties texte et JSON sont inchangées. Avec plusieurs, le
	texte enchaîne les rapports et le JSON devient une liste des mêmes objets. Le code de
	sortie vaut 1 dès qu'une seule archive est dangereuse.
	"""

	trusted = _trusted_from(args)
	if trusted is None:
		return EXIT_USAGE

	limits = _limits_from(args)
	targets = _collect_targets(args.targets, limits, args.remote_timeout)
	if targets is None:
		return EXIT_ERROR

	scanner = Scanner(limits, trusted=trusted)
	results: list[tuple[str, Verdict]] = [(name, scanner.inspect(target)) for name, target in targets]

	if args.sarif:
		print(render_sarif(results))
	elif args.json:
		documents = [json.loads(render_json(name, verdict, limits=limits)) for name, verdict in results]
		single = len(args.targets) == 1 and (
			is_url(args.targets[0]) or not Path(args.targets[0]).is_dir()
		)
		payload = documents[0] if single else documents
		print(json.dumps(payload, ensure_ascii=False, indent=2))
	else:
		if not results:
			print("\n  Aucune archive trouvée.\n")
		for name, verdict in results:
			print(render(name, verdict, limits=limits, **_render_options(args)))

	if args.exit_zero:
		return EXIT_OK
	return EXIT_OK if all(verdict.safe for _, verdict in results) else EXIT_UNSAFE


def _command_extract(args: argparse.Namespace) -> int:
	"""
	Description: Exécute la sous commande extract.
	Usage: interne à main.
	Inputs: args (Namespace) options analysées.
	Outputs: int code de sortie.
	"""

	if not args.archive.exists():
		print(f"zipguard: archive introuvable : {args.archive}", file=sys.stderr)
		return EXIT_ERROR

	trusted = _trusted_from(args)
	if trusted is None:
		return EXIT_USAGE

	limits = _limits_from(args)
	scanner = Scanner(limits, trusted=trusted)

	try:
		written = scanner.safe_extract(args.archive, args.destination, allow_links=args.allow_links)
	except (ExtractionRefused, QuotaExceeded) as error:
		if args.json:
			print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False, indent=2))
		else:
			print(
				render(str(args.archive), scanner.inspect(args.archive), limits=limits, **_render_options(args))
			)
			print(f"  Extraction refusée : {error}\n")
		return EXIT_UNSAFE
	except OSError as error:
		print(f"zipguard: extraction impossible : {error}", file=sys.stderr)
		return EXIT_ERROR

	if args.json:
		print(
			json.dumps(
				{
					"ok": True,
					"archive": str(args.archive),
					"destination": str(args.destination),
					"written_bytes": written,
				},
				ensure_ascii=False,
				indent=2,
			)
		)
	else:
		print("")
		print(f"  Extraction terminée dans {args.destination}")
		print(f"     octets écrits : {human_bytes(written)}")
		print("")

	return EXIT_OK


def _command_demo(args: argparse.Namespace) -> int:
	"""
	Description: Exécute la sous commande demo.
	Usage: interne à main.
	Inputs: args (Namespace) options analysées.
	Outputs: int code de sortie.
	"""

	try:
		result = build_demo_archive(
			args.output,
			text=args.text,
			megabytes=args.mb,
			archive_format=args.archive_format,
		)
	except ValueError as error:
		print(f"zipguard: {error}", file=sys.stderr)
		return EXIT_ERROR
	except OSError as error:
		print(f"zipguard: écriture impossible : {error}", file=sys.stderr)
		return EXIT_ERROR

	print("")
	print("  Démonstration créée")
	print(f"     fichier       : {result['path']}")
	print(f"     format        : {result['format']}")
	print(f"     décompressé   : {human_bytes(result['uncompressed'])}")
	print(f"     compressé     : {human_bytes(result['compressed'])}")
	print(f"     ratio         : {result['ratio']}x")
	print("")
	return EXIT_OK


def _command_serve(args: argparse.Namespace) -> int:
	"""
	Description: Exécute la sous commande serve.
	Usage: interne à main.
	Inputs: args (Namespace) options analysées.
	Outputs: int code de sortie.
	"""

	from .service import serve

	trusted = _trusted_from(args)
	if trusted is None:
		return EXIT_USAGE

	serve(
		limits=_limits_from(args),
		trusted=trusted,
		host=args.host,
		port=args.port,
		max_upload_bytes=args.max_upload_mb * 1_000_000,
		timeout=args.timeout,
		isolate=not args.no_isolate,
		read_timeout=args.read_timeout,
		max_concurrent=args.max_concurrent,
		max_memory_bytes=args.max_memory_mb * 1_000_000,
	)
	return EXIT_OK


def _command_bench(args: argparse.Namespace) -> int:
	"""
	Description: Exécute la sous commande bench.
	Usage: interne à main.
	Inputs: args (Namespace) options analysées.
	Outputs: int code de sortie.
	"""

	directory = args.keep or Path(tempfile.mkdtemp(prefix="zipguard-bench-"))
	try:
		results = run_bench(build_corpus(directory), repeat=args.repeat)
		if args.json:
			print(bench_json(results))
		else:
			print(render_bench(results, **_render_options(args)))
	finally:
		if args.keep is None:
			shutil.rmtree(directory, ignore_errors=True)

	return EXIT_OK


def _command_formats(_: argparse.Namespace) -> int:
	"""
	Description: Exécute la sous commande formats.
	Usage: interne à main.
	Inputs: ignoré.
	Outputs: int code de sortie.
	"""

	print("")
	print("  Formats inspectés par ZipGuard")
	for kind in supported_kinds():
		note = {
			"zip": "manifeste vérifiable, tailles déclarées",
			"7z": "manifeste, nécessite l'extra py7zr",
		}.get(kind, "tailles mesurées derrière un plafond de lecture")
		print(f"     {kind.ljust(10)} {note}")
	print("")
	print("  Le format est reconnu par signature, jamais par extension.")
	print("")
	return EXIT_OK


def _command_fingerprint(args: argparse.Namespace) -> int:
	"""
	Description: Exécute la sous commande fingerprint.
	Usage: interne à main.
	Inputs: args (Namespace) options analysées.
	Outputs: int code de sortie.

	La sortie reprend exactement le format de sha256sum : on peut la rediriger telle quelle
	dans une liste de confiance, et la relire avec sha256sum --check.
	"""

	status = EXIT_OK
	for archive in args.archives:
		try:
			print(f"{fingerprint(archive)}  {archive}")
		except OSError as error:
			print(f"zipguard: lecture impossible : {archive} ({error.strerror or error})", file=sys.stderr)
			status = EXIT_ERROR
	return status


_COMMANDS = {
	"scan": _command_scan,
	"extract": _command_extract,
	"demo": _command_demo,
	"serve": _command_serve,
	"bench": _command_bench,
	"formats": _command_formats,
	"fingerprint": _command_fingerprint,
}


def main(argv: list[str] | None = None) -> int:
	"""
	Description: Point d'entrée de la commande zipguard.
	Usage: python -m zipguard scan archive.zip.
	Inputs: argv (list[str] | None) arguments, sys.argv par défaut.
	Outputs: int code de sortie, 0 si l'opération réussit et l'archive est sûre.
	"""

	args = _build_parser().parse_args(argv)
	handler = _COMMANDS.get(args.command)
	if handler is None:  # pragma: no cover - argparse garantit une commande connue
		return EXIT_USAGE
	return handler(args)


if __name__ == "__main__":
	sys.exit(main())
