from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .demo import build_demo_archive
from .limits import Limits, human_bytes
from .report import render
from .scanner import Scanner


def _build_parser() -> argparse.ArgumentParser:
	"""
	Description: Construit l'interface en ligne de commande de ZipGuard.
	Usage: parser = _build_parser(); parser.parse_args().
	Inputs: aucun.
	Outputs: ArgumentParser configuré avec les sous-commandes scan et demo.
	"""

	parser = argparse.ArgumentParser(
		prog="zipguard",
		description="Inspecte des archives et illustre les bombes de décompression, sans danger.",
	)
	sub = parser.add_subparsers(dest="command", required=True)

	scan = sub.add_parser("scan", help="Inspecte une archive et rend un verdict.")
	scan.add_argument("archive", type=Path)
	scan.add_argument("--max-ratio", type=float, default=Limits.max_ratio)
	scan.add_argument("--max-total-mb", type=int, default=Limits.max_total_bytes // 1_000_000)

	demo = sub.add_parser("demo", help="Crée une archive de démonstration bornée.")
	demo.add_argument("output", type=Path)
	demo.add_argument("--text", default="zizi")
	demo.add_argument("--mb", type=int, default=10)

	return parser


def main(argv: list[str] | None = None) -> int:
	"""
	Description: Point d'entrée de la commande zipguard.
	Usage: python -m zipguard scan archive.zip.
	Inputs: argv (list[str] | None) arguments, sys.argv par défaut.
	Outputs: int code de sortie, 0 si l'opération réussit.
	"""

	args = _build_parser().parse_args(argv)

	if args.command == "scan":
		limits = Limits(
			max_ratio=args.max_ratio,
			max_total_bytes=args.max_total_mb * 1_000_000,
		)
		verdict = Scanner(limits).inspect(args.archive)
		print(render(str(args.archive), verdict))
		return 0 if verdict.safe else 1

	if args.command == "demo":
		result = build_demo_archive(args.output, text=args.text, megabytes=args.mb)
		print("")
		print("  🧪 Démonstration créée")
		print(f"     fichier       : {result['path']}")
		print(f"     décompressé   : {human_bytes(result['uncompressed'])}")
		print(f"     compressé     : {human_bytes(result['compressed'])}")
		print(f"     ratio         : {result['ratio']}x")
		print("")
		return 0

	return 2


if __name__ == "__main__":
	sys.exit(main())
