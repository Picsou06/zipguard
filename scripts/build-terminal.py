#!/usr/bin/env python3
"""
Description: Génère les cartes terminal du README, chacune montrant la vraie sortie de ZipGuard.
Usage: python scripts/build-terminal.py
Inputs: aucun, le script fabrique ses archives de démonstration puis appelle la ligne de commande.
Outputs: assets/scan-reel.svg et assets/scan-chiffree.svg réécrits sur place.

Un README qui recopie à la main la sortie d'un outil finit toujours par mentir : le format
change, la capture reste. Ici la carte est produite en exécutant réellement la commande,
donc elle est fausse au plus jusqu'au prochain lancement du script.

La première carte montre une bombe imbriquée bornée à quatre mégaoctets décompressés, le
même genre de cas que le banc d'essai : de quoi illustrer la détection sans fournir
d'arme. La seconde montre le refus d'une archive chiffrée, dont rien n'est lisible.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
APP = ROOT / "zipguard.app"

CHAR_WIDTH = 7.82
LINE_HEIGHT = 20
FONT_SIZE = 13.5
PADDING = 22
HEADER = 38

COLOURS = {
	"background": "#11151f",
	"chrome": "#1b2130",
	"title": "#8a93a6",
	"text": "#c7cede",
	"bright": "#f2f4f8",
	"dim": "#8a93a6",
	"danger": "#ff5f57",
	"safe": "#28c840",
	"accent": "#91EAE4",
	"prompt": "#28c840",
}


def build_sample(directory: Path) -> Path:
	"""
	Description: Fabrique l'archive montrée par la carte : une bombe cachée un niveau plus bas.
	Usage: build_sample(Path(tempdir)).
	Inputs: directory (Path) dossier de travail.
	Outputs: Path de l'archive externe.

	L'archive externe affiche un ratio parfaitement innocent : tout l'intérêt de la capture
	est de montrer que le refus vient de l'archive fille.
	"""

	inner = directory / "interne.zip"
	with zipfile.ZipFile(inner, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		archive.writestr("gros.txt", b"A" * 4_000_000)

	outer = directory / "livraison.zip"
	with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(inner, "notes.txt")
		archive.writestr("lisez-moi.txt", b"Rien de special ici.\n")
	return outer


def build_encrypted_sample(directory: Path) -> Path:
	"""
	Description: Fabrique une archive dont les entrées portent le drapeau de chiffrement.
	Usage: build_encrypted_sample(Path(tempdir)).
	Inputs: directory (Path) dossier de travail.
	Outputs: Path de l'archive.

	Rien n'est réellement chiffré : zipfile ne le sait pas, et ZipGuard ne juge que le
	drapeau. On réutilise l'outil du banc d'essai qui le pose.
	"""

	sys.path.insert(0, str(APP / "src"))
	from zipguard.bench import _flag_encrypted

	archive = directory / "sauvegarde.zip"
	with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
		handle.writestr("comptes.csv", b"date,montant\n" * 200)
		handle.writestr("notes.txt", b"Rien de special ici.\n")
	return _flag_encrypted(archive)


def capture(archive: Path, options: list[str]) -> tuple[str, list[str]]:
	"""
	Description: Lance la vraie ligne de commande et récupère sa sortie telle quelle.
	Usage: command, lines = capture(archive, ["--max-ratio", "20"]).
	Inputs: archive (Path) archive à inspecter, options (list[str]) options de scan.
	Outputs: tuple de la commande affichée et des lignes de sortie.
	"""

	arguments = ["scan", archive.name, *options, "--no-color"]
	environment = {
		**os.environ,
		"PYTHONPATH": str(APP / "src"),
		"PYTHONIOENCODING": "utf-8",
	}
	completed = subprocess.run(
		[sys.executable, "-m", "zipguard", *arguments],
		cwd=archive.parent,
		env=environment,
		capture_output=True,
		text=True,
		encoding="utf-8",
		check=False,
	)
	if completed.returncode not in (0, 1):
		raise SystemExit(f"La commande a échoué ({completed.returncode}) : {completed.stderr}")

	lines = [line.rstrip() for line in completed.stdout.splitlines()]
	while lines and not lines[0].strip():
		lines.pop(0)
	while lines and not lines[-1].strip():
		lines.pop()
	return "zipguard " + " ".join(arguments), lines


def colour_for(line: str) -> tuple[str, str]:
	"""
	Description: Choisit la couleur et la graisse d'une ligne de la carte.
	Usage: fill, weight = colour_for(line).
	Inputs: line (str) ligne de sortie.
	Outputs: tuple de la couleur et de la graisse.
	"""

	if "DANGEREUSE" in line or line.strip().startswith("⛔"):
		return COLOURS["danger"], "700"
	if "SÛRE" in line:
		return COLOURS["safe"], "700"
	if line.strip() in {"raisons du refus", "archives imbriquées"}:
		return COLOURS["bright"], "700"
	if line.strip().startswith(("•", "└")):
		return COLOURS["dim"], "400"
	if "─" in line:
		return COLOURS["chrome"], "400"
	if "ZipGuard" in line:
		return COLOURS["accent"], "700"
	return COLOURS["text"], "400"


def escape(text: str) -> str:
	"""
	Description: Échappe les caractères réservés du XML.
	Usage: escape("a < b").
	Inputs: text (str) texte brut.
	Outputs: str sûre à insérer dans le SVG.
	"""

	return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build(command: str, lines: list[str], label: str) -> str:
	"""
	Description: Assemble la carte terminal autour de la sortie capturée.
	Usage: build(command, lines, "Sortie réelle de zipguard scan").
	Inputs: command (str) commande affichée, lines (list[str]) sortie, label (str) description accessible.
	Outputs: str contenu du fichier SVG.
	"""

	rendered = [f"$ {command}", ""] + lines
	columns = max(len(line) for line in rendered)
	width = round(columns * CHAR_WIDTH + PADDING * 2)
	height = round(HEADER + PADDING + len(rendered) * LINE_HEIGHT + PADDING)
	total = len(rendered)

	body = []
	for index, line in enumerate(rendered):
		y = HEADER + PADDING + index * LINE_HEIGHT + FONT_SIZE
		delay = round(0.08 * index, 2)

		if index == 0:
			prefix = f'<tspan fill="{COLOURS["prompt"]}">$</tspan>'
			content = f"{prefix} {escape(line[2:])}"
			fill, weight = COLOURS["bright"], "400"
		else:
			content = escape(line)
			fill, weight = colour_for(line)

		body.append(
			f'\t\t<text xml:space="preserve" x="{PADDING}" y="{y}" fill="{fill}"'
			f' font-weight="{weight}" opacity="0">'
			f"{content}"
			f'<animate attributeName="opacity" values="0;0;1;1" '
			f'keyTimes="0;{min(delay / 12, 0.98):.4f};{min((delay + 0.25) / 12, 0.99):.4f};1" '
			f'dur="12s" repeatCount="indefinite"/>'
			f"</text>"
		)

	return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}"
	width="{width}" height="{height}" role="img"
	aria-label="{escape(label)}">
	<rect x="0" y="0" width="{width}" height="{height}" rx="14" fill="{COLOURS['background']}"/>
	<rect x="0" y="0" width="{width}" height="{HEADER}" rx="14" fill="{COLOURS['chrome']}"/>
	<rect x="0" y="{HEADER - 14}" width="{width}" height="14" fill="{COLOURS['chrome']}"/>
	<circle cx="24" cy="19" r="6" fill="#ff5f57"/>
	<circle cx="46" cy="19" r="6" fill="#febc2e"/>
	<circle cx="68" cy="19" r="6" fill="#28c840"/>
	<text x="{width / 2}" y="24" text-anchor="middle" font-family="Fira Code, Consolas, monospace"
		font-size="12" fill="{COLOURS['title']}">zipguard — sortie réelle, {total} lignes</text>

	<g font-family="Fira Code, Consolas, monospace" font-size="{FONT_SIZE}" xml:space="preserve">
{chr(10).join(body)}
	</g>
</svg>
"""


def main() -> int:
	"""
	Description: Point d'entrée du générateur.
	Usage: python scripts/build-terminal.py.
	Inputs: aucun.
	Outputs: int code de sortie.
	"""

	cards = [
		(
			"scan-reel.svg",
			build_sample,
			["--max-ratio", "20"],
			"Sortie réelle de zipguard scan sur une archive à bombe imbriquée",
		),
		(
			"scan-chiffree.svg",
			build_encrypted_sample,
			[],
			"Sortie réelle de zipguard scan sur une archive chiffrée",
		),
	]

	ASSETS.mkdir(parents=True, exist_ok=True)
	for filename, sample, options, label in cards:
		workdir = Path(tempfile.mkdtemp(prefix="zipguard-capture-"))
		try:
			command, lines = capture(sample(workdir), options)
			target = ASSETS / filename
			target.write_text(build(command, lines, label), encoding="utf-8")
		finally:
			shutil.rmtree(workdir, ignore_errors=True)
		print(f"{target.relative_to(ROOT)} écrit ({target.stat().st_size / 1024:.1f} Kio)")
	return 0


if __name__ == "__main__":
	sys.exit(main())
