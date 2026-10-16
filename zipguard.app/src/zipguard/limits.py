from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
	"""
	Description: Seuils de sécurité appliqués lors de l'inspection d'une archive.
	Usage: Limits() pour les valeurs par défaut, ou Limits(max_ratio=50) pour durcir.
	Inputs: max_total_bytes (int), max_entry_bytes (int), max_ratio (float), max_entries (int), max_depth (int).
	Outputs: instance immuable transportant les seuils.
	"""

	max_total_bytes: int = 1_000_000_000
	max_entry_bytes: int = 200_000_000
	max_ratio: float = 100.0
	max_entries: int = 10_000
	max_depth: int = 2


@dataclass(frozen=True)
class Verdict:
	"""
	Description: Résultat d'une inspection, sûr ou dangereux, avec la raison.
	Usage: retourné par Scanner.inspect ; lire .safe puis .reasons.
	Inputs: safe (bool), reasons (list[str]), stats (dict).
	Outputs: structure sérialisable décrivant la décision.
	"""

	safe: bool
	reasons: list[str]
	stats: dict


def human_bytes(value: float) -> str:
	"""
	Description: Formate un nombre d'octets en unité lisible.
	Usage: human_bytes(1536) -> "1.5 KiB".
	Inputs: value (float) nombre d'octets.
	Outputs: str formatée avec l'unité binaire adaptée.
	"""

	units = ["o", "KiB", "MiB", "GiB", "TiB", "PiB"]
	size = float(value)
	for unit in units:
		if size < 1024 or unit == units[-1]:
			return f"{size:.1f} {unit}"
		size /= 1024
	return f"{size:.1f} {units[-1]}"
