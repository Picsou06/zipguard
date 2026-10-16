from __future__ import annotations

import zipfile
from pathlib import Path

from .limits import Limits, Verdict


class Scanner:
	"""
	Description: Inspecte une archive ZIP sans la décompresser aveuglément et rend un verdict.
	Usage: Scanner(Limits()).inspect(Path("archive.zip")).
	Inputs: limits (Limits) seuils de sécurité.
	Outputs: Verdict indiquant si l'archive peut être traitée sans risque.
	"""

	def __init__(self, limits: Limits | None = None) -> None:
		self.limits = limits or Limits()

	def inspect(self, path: Path) -> Verdict:
		"""
		Description: Analyse les métadonnées d'une archive et compare aux seuils.
		Usage: scanner.inspect(Path("suspect.zip")).
		Inputs: path (Path) chemin de l'archive à inspecter.
		Outputs: Verdict avec safe, reasons et stats.
		"""

		reasons: list[str] = []

		if not zipfile.is_zipfile(path):
			return Verdict(False, ["Le fichier n'est pas une archive ZIP valide."], {})

		with zipfile.ZipFile(path) as archive:
			infos = archive.infolist()
			total_uncompressed = sum(i.file_size for i in infos)
			total_compressed = sum(i.compress_size for i in infos) or 1
			ratio = total_uncompressed / total_compressed
			biggest = max((i.file_size for i in infos), default=0)
			nested = sum(1 for i in infos if i.filename.lower().endswith(".zip"))

			stats = {
				"entries": len(infos),
				"total_uncompressed": total_uncompressed,
				"total_compressed": total_compressed,
				"ratio": round(ratio, 2),
				"biggest_entry": biggest,
				"nested_archives": nested,
			}

			if len(infos) > self.limits.max_entries:
				reasons.append(
					f"Trop d'entrées : {len(infos)} > {self.limits.max_entries}."
				)
			if total_uncompressed > self.limits.max_total_bytes:
				reasons.append(
					f"Taille décompressée annoncée trop grande : {total_uncompressed} o."
				)
			if biggest > self.limits.max_entry_bytes:
				reasons.append(
					f"Une entrée dépasse la limite par fichier : {biggest} o."
				)
			if ratio > self.limits.max_ratio:
				reasons.append(
					f"Ratio de compression anormal : {ratio:.1f}x > {self.limits.max_ratio}x."
				)
			if nested > 0 and self.limits.max_depth < 2:
				reasons.append(
					f"Archives imbriquées détectées ({nested}) et profondeur interdite."
				)

		return Verdict(len(reasons) == 0, reasons, stats)

	def safe_extract(self, path: Path, destination: Path) -> int:
		"""
		Description: Extrait une archive jugée sûre en plafonnant les octets écrits par entrée.
		Usage: scanner.safe_extract(Path("ok.zip"), Path("out")).
		Inputs: path (Path) archive, destination (Path) dossier de sortie.
		Outputs: int nombre total d'octets réellement écrits.
		"""

		verdict = self.inspect(path)
		if not verdict.safe:
			raise ValueError("Extraction refusée : " + " ".join(verdict.reasons))

		destination.mkdir(parents=True, exist_ok=True)
		written = 0
		with zipfile.ZipFile(path) as archive:
			for info in archive.infolist():
				target = self._resolve(destination, info.filename)
				if info.is_dir():
					target.mkdir(parents=True, exist_ok=True)
					continue
				target.parent.mkdir(parents=True, exist_ok=True)
				written += self._stream_entry(archive, info, target)
		return written

	def _stream_entry(self, archive: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path) -> int:
		"""
		Description: Copie une entrée par blocs en coupant au dépassement de la limite.
		Usage: interne à safe_extract.
		Inputs: archive, info (ZipInfo), target (Path) destination du fichier.
		Outputs: int octets écrits pour cette entrée.
		"""

		cap = self.limits.max_entry_bytes
		written = 0
		with archive.open(info) as source, open(target, "wb") as sink:
			while True:
				chunk = source.read(65536)
				if not chunk:
					break
				written += len(chunk)
				if written > cap:
					raise ValueError(
						f"Entrée {info.filename} dépasse la limite pendant l'extraction."
					)
				sink.write(chunk)
		return written

	@staticmethod
	def _resolve(destination: Path, name: str) -> Path:
		"""
		Description: Résout un chemin d'entrée en empêchant toute sortie du dossier cible.
		Usage: interne, protège contre le path traversal (Zip Slip).
		Inputs: destination (Path) racine autorisée, name (str) nom d'entrée.
		Outputs: Path sûr contenu dans destination.
		"""

		resolved = (destination / name).resolve()
		root = destination.resolve()
		if root != resolved and root not in resolved.parents:
			raise ValueError(f"Chemin d'entrée hors du dossier cible : {name}")
		return resolved
