from __future__ import annotations

from dataclasses import dataclass, field

# Chaque refus porte un code stable, en plus de sa phrase : les phrases sont faites pour
# être lues et peuvent changer, les codes sont faits pour être triés par une machine (sortie
# JSON, règles du rapport SARIF). Ajouter un code est sans risque, en renommer un casse.
REASON_CODES: dict[str, str] = {
	"unsupported": "Format non reconnu",
	"unreadable": "Archive illisible ou corrompue",
	"read_cap": "Lecture coupée au plafond",
	"too_many_entries": "Trop d'entrées",
	"total_size": "Taille décompressée trop grande",
	"entry_size": "Entrée trop grande",
	"ratio": "Ratio de compression anormal",
	"encrypted": "Archive chiffrée, contenu invérifiable",
	"depth": "Imbrication trop profonde pour être vérifiée",
	"nested_budget": "Budget d'inspection des archives imbriquées épuisé",
	"nested": "Archive imbriquée dangereuse",
	"nested_cut": "Archive imbriquée coupée pendant la lecture",
	"download_cap": "Plafond de téléchargement atteint",
	"download_timeout": "Délai total de lecture distante dépassé",
	"memory": "Mémoire épuisée pendant l'analyse",
}


@dataclass(frozen=True)
class Limits:
	"""
	Description: Seuils de sécurité appliqués lors de l'inspection puis de l'extraction d'une archive.
	Usage: Limits() pour les valeurs par défaut, ou Limits(max_ratio=50) pour durcir.
	Inputs: max_total_bytes (int), max_entry_bytes (int), max_ratio (float), max_entries (int), max_depth (int), max_extract_bytes (int), min_free_bytes (int), max_nested_scans (int), max_buffer_bytes (int), max_download_bytes (int).
	Outputs: instance immuable transportant les seuils.

	Les cinq premiers seuils décident du verdict, les trois suivants bornent le travail réel
	fait sur le disque. Aucun n'est négociable au moment de l'extraction : un verdict sûr
	n'autorise pas à écrire sans compter. Les deux derniers ne servent qu'à l'inspection
	sans disque d'une archive distante : la mémoire accordée à une archive imbriquée, et le
	volume total que l'on accepte de télécharger.
	"""

	max_total_bytes: int = 1_000_000_000
	max_entry_bytes: int = 200_000_000
	max_ratio: float = 100.0
	max_entries: int = 10_000
	max_depth: int = 2
	max_extract_bytes: int = 1_000_000_000
	min_free_bytes: int = 64_000_000
	max_nested_scans: int = 64
	max_buffer_bytes: int = 64_000_000
	max_download_bytes: int = 200_000_000

	def as_dict(self) -> dict:
		"""
		Description: Expose les seuils sous forme sérialisable, pour la sortie JSON et l'API.
		Usage: json.dumps(limits.as_dict()).
		Inputs: aucun.
		Outputs: dict des seuils, clés identiques aux champs.
		"""

		return {
			"max_total_bytes": self.max_total_bytes,
			"max_entry_bytes": self.max_entry_bytes,
			"max_ratio": self.max_ratio,
			"max_entries": self.max_entries,
			"max_depth": self.max_depth,
			"max_extract_bytes": self.max_extract_bytes,
			"min_free_bytes": self.min_free_bytes,
			"max_nested_scans": self.max_nested_scans,
			"max_buffer_bytes": self.max_buffer_bytes,
			"max_download_bytes": self.max_download_bytes,
		}


@dataclass(frozen=True)
class Verdict:
	"""
	Description: Résultat d'une inspection, sûr ou dangereux, avec la raison et les archives filles.
	Usage: retourné par Scanner.inspect ; lire .safe puis .reasons, ou .codes pour une machine.
	Inputs: safe (bool), reasons (list[str]), stats (dict), children (list[Verdict]), codes (list[str]) un code de REASON_CODES par raison.
	Outputs: structure sérialisable décrivant la décision, récursivement.
	"""

	safe: bool
	reasons: list[str]
	stats: dict
	children: list[Verdict] = field(default_factory=list)
	codes: list[str] = field(default_factory=list)

	@classmethod
	def refused(cls, stats: dict, code: str, message: str) -> Verdict:
		"""
		Description: Construit un verdict dangereux portant une seule raison.
		Usage: Verdict.refused(base, "unreadable", "Archive illisible.").
		Inputs: stats (dict), code (str) clé de REASON_CODES, message (str) raison lisible.
		Outputs: Verdict dangereux.
		"""

		return cls(False, [message], stats, codes=[code])

	def as_dict(self) -> dict:
		"""
		Description: Convertit le verdict et toute sa descendance en structure JSON.
		Usage: json.dumps(verdict.as_dict()).
		Inputs: aucun.
		Outputs: dict imbriqué, prêt pour json.dumps.
		"""

		return {
			"safe": self.safe,
			"verdict": "SURE" if self.safe else "DANGEREUSE",
			"reasons": list(self.reasons),
			"codes": list(self.codes),
			"stats": dict(self.stats),
			"children": [child.as_dict() for child in self.children],
		}

	def walk(self):
		"""
		Description: Parcourt le verdict puis toutes les archives imbriquées, en profondeur.
		Usage: for node in verdict.walk(): ...
		Inputs: aucun.
		Outputs: générateur de Verdict, le parent avant ses enfants.
		"""

		yield self
		for child in self.children:
			yield from child.walk()


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
