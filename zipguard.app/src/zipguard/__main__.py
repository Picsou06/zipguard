from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from . import __version__
from .bench import bench_json, build_corpus, render_bench, run_bench
from .demo import FORMATS, build_demo_archive
from .formats import supported_kinds
from .limits import Limits, human_bytes
from .report import render, render_json
from .scanner import ExtractionRefused, QuotaExceeded, Scanner

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
	parser.add_argument(
		"--max-total-mb", type=int, default=defaults.max_total_bytes // 1_000_000
	)
	parser.add_argument(
		"--max-entry-mb", type=int, default=defaults.max_entry_bytes // 1_000_000
	)
	parser.add_argument("--max-entries", type=int, default=defaults.max_entries)
	parser.add_argument("--max-depth", type=int, default=defaults.max_depth)


def _add_render_flags(parser: argparse.ArgumentParser) -> None:
	"""
	Description: Ajoute les options de mise en forme de la sortie.
	Usage: _add_render_flags(scan_parser).
	Inputs: parser (ArgumentParser) sous commande à enrichir.
	Outputs: None, le parser est modifié sur place.
	"""

	parser.add_argument("--json", action="store_true", help="Sortie JSON au lieu du rapport texte.")
	parser.add_argument("--no-color", action="store_true", help="Désactive les couleurs ANSI.")
	parser.add_argument("--ascii", action="store_true", help="Remplace les pictogrammes par de l'ASCII.")


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

	return Limits(
		max_total_bytes=args.max_total_mb * 1_000_000,
		max_entry_bytes=args.max_entry_mb * 1_000_000,
		max_ratio=args.max_ratio,
		max_entries=args.max_entries,
		max_depth=args.max_depth,
		max_extract_bytes=(
			defaults.max_extract_bytes if extract_mb is None else extract_mb * 1_000_000
		),
		min_free_bytes=(defaults.min_free_bytes if free_mb is None else free_mb * 1_000_000),
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

	scan = sub.add_parser("scan", help="Inspecte une archive et rend un verdict.")
	scan.add_argument("archive", type=Path)
	_add_threshold_flags(scan)
	_add_render_flags(scan)

	extract = sub.add_parser("extract", help="Extrait une archive jugée sûre, en comptant les octets.")
	extract.add_argument("archive", type=Path)
	extract.add_argument("destination", type=Path)
	_add_threshold_flags(extract)
	_add_render_flags(extract)
	extract.add_argument("--max-extract-mb", type=int, default=None)
	extract.add_argument("--min-free-mb", type=int, default=None)

	demo = sub.add_parser("demo", help="Crée une archive de démonstration bornée.")
	demo.add_argument("output", type=Path)
	demo.add_argument("--text", default="zizi")
	demo.add_argument("--mb", type=int, default=10)
	demo.add_argument("--format", dest="archive_format", choices=FORMATS, default="zip")

	serve = sub.add_parser("serve", help="Expose le scanner en petit service HTTP local.")
	serve.add_argument("--host", default="127.0.0.1")
	serve.add_argument("--port", type=int, default=8723)
	serve.add_argument("--max-upload-mb", type=int, default=64)
	serve.add_argument("--timeout", type=float, default=30.0)
	serve.add_argument(
		"--no-isolate",
		action="store_true",
		help="Analyse dans le processus du serveur au lieu d'un worker jetable.",
	)
	_add_threshold_flags(serve)

	bench = sub.add_parser("bench", help="Mesure le temps que met chaque garde fou à trancher.")
	bench.add_argument("--repeat", type=int, default=3)
	bench.add_argument("--keep", type=Path, default=None, help="Conserve le corpus dans ce dossier.")
	_add_render_flags(bench)

	sub.add_parser("formats", help="Liste les formats d'archive pris en charge.")

	return parser


def _command_scan(args: argparse.Namespace) -> int:
	"""
	Description: Exécute la sous commande scan.
	Usage: interne à main.
	Inputs: args (Namespace) options analysées.
	Outputs: int code de sortie.
	"""

	if not args.archive.exists():
		print(f"zipguard: archive introuvable : {args.archive}", file=sys.stderr)
		return EXIT_ERROR

	limits = _limits_from(args)
	verdict = Scanner(limits).inspect(args.archive)

	if args.json:
		print(render_json(str(args.archive), verdict, limits=limits, indent=2))
	else:
		print(render(str(args.archive), verdict, limits=limits, **_render_options(args)))

	return EXIT_OK if verdict.safe else EXIT_UNSAFE


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

	limits = _limits_from(args)
	scanner = Scanner(limits)

	try:
		written = scanner.safe_extract(args.archive, args.destination)
	except (ExtractionRefused, QuotaExceeded) as error:
		if args.json:
			print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False, indent=2))
		else:
			print(render(str(args.archive), scanner.inspect(args.archive), limits=limits, **_render_options(args)))
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

	serve(
		limits=_limits_from(args),
		host=args.host,
		port=args.port,
		max_upload_bytes=args.max_upload_mb * 1_000_000,
		timeout=args.timeout,
		isolate=not args.no_isolate,
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


_COMMANDS = {
	"scan": _command_scan,
	"extract": _command_extract,
	"demo": _command_demo,
	"serve": _command_serve,
	"bench": _command_bench,
	"formats": _command_formats,
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
