from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from pathlib import Path

from .sources import Source, as_source

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def fingerprint(target: Source | Path) -> str:
	"""
	Description: Calcule l'empreinte SHA-256 d'une archive, lue par blocs.
	Usage: fingerprint(Path("donnees.tar.gz")).
	Inputs: target (Source | Path) archive.
	Outputs: str empreinte hexadécimale en minuscules.

	L'empreinte porte sur les octets compressés tels qu'ils sont stockés : c'est ce que
	sha256sum calcule, donc une liste produite par sha256sum se lit telle quelle.
	"""

	digest = hashlib.sha256()
	with as_source(target).open() as stream:
		while True:
			chunk = stream.read(1 << 20)
			if not chunk:
				break
			digest.update(chunk)
	return digest.hexdigest()


def parse_allowlist(lines: Iterable[str], origin: str = "liste") -> frozenset[str]:
	"""
	Description: Lit une liste d'empreintes de confiance, au format de sha256sum.
	Usage: parse_allowlist(open("confiance.txt")).
	Inputs: lines (Iterable[str]) lignes du fichier, origin (str) nom affiché dans les erreurs.
	Outputs: frozenset[str] des empreintes, en minuscules.

	Chaque ligne commence par une empreinte SHA-256 ; ce qui suit est un commentaire libre,
	souvent le nom du fichier. Les lignes vides et celles qui commencent par # sont
	ignorées. Une ligne mal formée lève ValueError plutôt que d'être sautée : une liste de
	confiance qui se lit à moitié en silence finit par faire confiance à autre chose que
	ce qu'on croit.
	"""

	hashes: set[str] = set()
	for number, raw in enumerate(lines, start=1):
		line = raw.strip()
		if not line or line.startswith("#"):
			continue
		token = line.split()[0].lstrip("\\")
		if not _HEX64.match(token):
			raise ValueError(f"{origin}, ligne {number} : empreinte SHA-256 attendue, lu {token[:20]!r}.")
		hashes.add(token.lower())
	return frozenset(hashes)


def load_allowlist(path: Path) -> frozenset[str]:
	"""
	Description: Charge une liste d'empreintes de confiance depuis un fichier.
	Usage: load_allowlist(Path("confiance.txt")).
	Inputs: path (Path) fichier au format de sha256sum.
	Outputs: frozenset[str] des empreintes.
	"""

	path = Path(path)
	with open(path, encoding="utf-8") as handle:
		return parse_allowlist(handle, origin=str(path))
