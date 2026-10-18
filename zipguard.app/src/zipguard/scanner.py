from __future__ import annotations

import contextlib
import ntpath
import os
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .formats import (
	Archive,
	Entry,
	ReadCapExceeded,
	UnsupportedArchive,
	open_archive,
	sniff_kind,
)
from .limits import Limits, Verdict, human_bytes

CHUNK = 65536
FREE_SPACE_CHECK_EVERY = 8 * 1024 * 1024

_READ_ERRORS = (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, ValueError)


class ExtractionRefused(ValueError):
	"""
	Description: Signale un refus d'extraction décidé avant d'écrire quoi que ce soit.
	Usage: levée par Scanner.safe_extract sur une archive dangereuse ou un chemin d'évasion.
	Inputs: message (str) raison du refus.
	Outputs: exception dérivant de ValueError pour rester compatible avec l'API historique.
	"""


class QuotaExceeded(ValueError):
	"""
	Description: Signale qu'une extraction a dépassé un quota d'octets ou la marge de disque libre.
	Usage: levée pendant l'écriture ; les fichiers déjà écrits sont retirés avant de remonter.
	Inputs: message (str) quota franchi.
	Outputs: exception dérivant de ValueError.
	"""


@dataclass
class _Budget:
	"""
	Description: Compteur partagé bornant le nombre d'archives imbriquées inspectées.
	Usage: budget = _Budget(64) ; budget.take().
	Inputs: left (int) nombre d'inspections encore autorisées.
	Outputs: objet mutable transmis le long de la récursion.

	Sans ce compteur, une archive contenant dix mille archives vides coûterait dix mille
	extractions temporaires : un déni de service par le travail, pas par la taille.
	"""

	left: int

	def take(self) -> bool:
		if self.left <= 0:
			return False
		self.left -= 1
		return True


@dataclass(frozen=True)
class _Planned:
	"""
	Description: Entrée validée par la passe préalable, prête à être écrite.
	Usage: produite par Scanner._preflight, consommée par Scanner._stage.
	Inputs: entry (Entry), parts (tuple[str, ...]) chemin normalisé, kind (str) dir, file ou link, link_target (str).
	Outputs: structure immuable.
	"""

	entry: Entry
	parts: tuple[str, ...]
	kind: str
	link_target: str = ""


class Scanner:
	"""
	Description: Inspecte une archive sans la décompresser aveuglément et rend un verdict.
	Usage: Scanner(Limits()).inspect(Path("archive.zip")).
	Inputs: limits (Limits) seuils de sécurité.
	Outputs: Verdict indiquant si l'archive peut être traitée sans risque.

	Le scanner ne connaît aucun format : il parle à un adaptateur commun, ce qui fait que
	zip, tar, tar.gz, tar.bz2, tar.xz, gz, bz2, xz et 7z passent exactement les mêmes seuils.
	"""

	def __init__(self, limits: Limits | None = None) -> None:
		self.limits = limits or Limits()

	# ------------------------------------------------------------------ inspection

	def inspect(
		self,
		path: Path,
		*,
		depth: int = 0,
		name: str | None = None,
		budget: _Budget | None = None,
	) -> Verdict:
		"""
		Description: Analyse une archive, descend dans celles qu'elle contient, et compare aux seuils.
		Usage: scanner.inspect(Path("suspect.zip")).
		Inputs: path (Path) archive, depth (int) profondeur courante, name (str) nom affiché, budget (_Budget) compteur interne.
		Outputs: Verdict avec safe, reasons, stats et children.
		"""

		path = Path(path)
		label = name if name is not None else path.name
		budget = budget or _Budget(self.limits.max_nested_scans)
		base = {"name": label, "depth": depth}

		try:
			handle = open_archive(path, read_cap=self.limits.max_total_bytes)
		except UnsupportedArchive as error:
			return Verdict(False, [str(error)], base)
		except _READ_ERRORS as error:
			return Verdict(False, [f"Archive illisible : {error}"], base)

		with handle:
			try:
				entries = handle.entries()
			except ReadCapExceeded as error:
				reason = (
					f"Lecture coupée après {human_bytes(error.read)} : le contenu dépasse "
					f"le plafond de {human_bytes(error.cap)}."
				)
				return Verdict(
					False,
					[reason],
					{
						**base,
						"kind": handle.kind,
						"measured": True,
						"total_uncompressed": error.read,
						"cut_at_cap": True,
					},
				)
			except _READ_ERRORS as error:
				return Verdict(
					False,
					[f"Archive illisible ou corrompue : {error}"],
					{**base, "kind": handle.kind},
				)

			candidates = self._nested_candidates(handle, entries)
			stats = self._build_stats(handle, entries, base, len(candidates))
			reasons = self._threshold_reasons(stats)
			children = self._descend(handle, candidates, depth, budget, reasons)

		return Verdict(not reasons, reasons, stats, children)

	def _build_stats(
		self,
		handle: Archive,
		entries: list[Entry],
		base: dict,
		nested: int,
	) -> dict:
		"""
		Description: Rassemble les chiffres de l'archive, mesurés ou déclarés selon le format.
		Usage: interne à inspect.
		Inputs: handle (Archive), entries (list[Entry]), base (dict) nom et profondeur, nested (int).
		Outputs: dict de statistiques sérialisable.
		"""

		total_uncompressed = sum(entry.size for entry in entries)
		total_compressed = max(1, handle.compressed_total)
		return {
			**base,
			"kind": handle.kind,
			"measured": handle.sizes_are_measured,
			"entries": len(entries),
			"total_uncompressed": total_uncompressed,
			"total_compressed": total_compressed,
			"ratio": round(total_uncompressed / total_compressed, 2),
			"biggest_entry": max((entry.size for entry in entries), default=0),
			"nested_archives": nested,
			"links": sum(1 for entry in entries if entry.is_link),
			"cut_at_cap": False,
		}

	def _threshold_reasons(self, stats: dict) -> list[str]:
		"""
		Description: Confronte les statistiques aux seuils et formule chaque refus en clair.
		Usage: interne à inspect.
		Inputs: stats (dict) chiffres de l'archive.
		Outputs: list[str] des raisons, vide si tout passe.
		"""

		limits = self.limits
		reasons: list[str] = []

		if stats["entries"] > limits.max_entries:
			reasons.append(f"Trop d'entrées : {stats['entries']} > {limits.max_entries}.")
		if stats["total_uncompressed"] > limits.max_total_bytes:
			reasons.append(
				f"Taille décompressée trop grande : {human_bytes(stats['total_uncompressed'])} "
				f"> {human_bytes(limits.max_total_bytes)}."
			)
		if stats["biggest_entry"] > limits.max_entry_bytes:
			reasons.append(
				f"Une entrée dépasse la limite par fichier : "
				f"{human_bytes(stats['biggest_entry'])} > {human_bytes(limits.max_entry_bytes)}."
			)
		if stats["ratio"] > limits.max_ratio:
			reasons.append(f"Ratio de compression anormal : {stats['ratio']:.1f}x > {limits.max_ratio}x.")
		return reasons

	def _nested_candidates(self, handle: Archive, entries: list[Entry]) -> list[Entry]:
		"""
		Description: Repère les entrées qui sont elles mêmes des archives, par signature.
		Usage: interne à inspect.
		Inputs: handle (Archive) archive ouverte, entries (list[Entry]) inventaire.
		Outputs: list[Entry] des entrées à inspecter récursivement.

		Le nom de l'entrée n'entre pas en jeu : une bombe renommée en notes.txt est repérée
		exactement comme si elle s'appelait bombe.zip.
		"""

		candidates = []
		for entry in entries:
			if entry.is_dir or entry.is_link or entry.size <= 0:
				continue
			if sniff_kind(handle.head(entry)) is not None:
				candidates.append(entry)
		return candidates

	def _descend(
		self,
		handle: Archive,
		candidates: list[Entry],
		depth: int,
		budget: _Budget,
		reasons: list[str],
	) -> list[Verdict]:
		"""
		Description: Inspecte les archives imbriquées, ou refuse quand la profondeur l'interdit.
		Usage: interne à inspect.
		Inputs: handle (Archive), candidates (list[Entry]), depth (int), budget (_Budget), reasons (list[str]) enrichie sur place.
		Outputs: list[Verdict] des archives filles inspectées.
		"""

		if not candidates:
			return []

		if depth >= self.limits.max_depth:
			reasons.append(
				f"{len(candidates)} archive(s) imbriquée(s) non inspectée(s) : profondeur "
				f"maximale de {self.limits.max_depth} atteinte, donc contenu invérifiable."
			)
			return []

		children: list[Verdict] = []
		for entry in candidates:
			if not budget.take():
				reasons.append(
					f"Budget d'inspection épuisé après {self.limits.max_nested_scans} "
					"archives imbriquées : le reste est invérifiable."
				)
				break
			child = self._inspect_nested(handle, entry, depth + 1, budget)
			children.append(child)
			if not child.safe:
				detail = " ".join(child.reasons)
				reasons.append(f"Archive imbriquée dangereuse — {entry.name} : {detail}")
		return children

	def _inspect_nested(
		self,
		handle: Archive,
		entry: Entry,
		depth: int,
		budget: _Budget,
	) -> Verdict:
		"""
		Description: Recopie une entrée imbriquée dans un fichier temporaire borné, puis l'inspecte.
		Usage: interne à _descend.
		Inputs: handle (Archive), entry (Entry) archive fille, depth (int), budget (_Budget).
		Outputs: Verdict de l'archive fille.

		La copie est plafonnée : une archive fille qui gonfle pendant la lecture est refusée
		sans jamais remplir le disque de travail.
		"""

		base = {"name": entry.name, "depth": depth}
		cap = min(self.limits.max_entry_bytes, self.limits.max_total_bytes)
		temporary = Path(tempfile.mkdtemp(prefix="zipguard-")) / "imbriquee.bin"

		try:
			copied = self._copy_capped(handle, entry, temporary, cap)
			if copied is None:
				return Verdict(
					False,
					[f"Archive imbriquée coupée à {human_bytes(cap)} pendant la lecture."],
					base,
				)
			return self.inspect(temporary, depth=depth, name=entry.name, budget=budget)
		except _READ_ERRORS as error:
			return Verdict(False, [f"Archive imbriquée illisible : {error}"], base)
		finally:
			shutil.rmtree(temporary.parent, ignore_errors=True)

	@staticmethod
	def _copy_capped(handle: Archive, entry: Entry, target: Path, cap: int) -> int | None:
		"""
		Description: Copie une entrée vers un fichier en s'arrêtant net au plafond.
		Usage: interne à _inspect_nested.
		Inputs: handle (Archive), entry (Entry), target (Path), cap (int) plafond d'octets.
		Outputs: int octets copiés, ou None si le plafond a été franchi.
		"""

		written = 0
		with handle.open(entry) as source, open(target, "wb") as sink:
			while True:
				chunk = source.read(CHUNK)
				if not chunk:
					break
				written += len(chunk)
				if written > cap:
					return None
				sink.write(chunk)
		return written

	# ------------------------------------------------------------------ extraction

	def safe_extract(self, path: Path, destination: Path, *, allow_links: bool = False) -> int:
		"""
		Description: Extrait une archive jugée sûre en comptant chaque octet écrit sur le disque.
		Usage: scanner.safe_extract(Path("ok.zip"), Path("out")).
		Inputs: path (Path) archive, destination (Path) dossier de sortie, allow_links (bool) accepte les liens symboliques restant dans l'arborescence.
		Outputs: int nombre total d'octets réellement écrits.

		Le verdict ne suffit pas : un manifeste peut mentir, donc l'écriture est recomptée en
		direct et toute dérive annule l'extraction. L'archive est d'abord recopiée dans un
		dossier privé, et c'est cette copie qui est inspectée puis extraite : le fichier ne peut
		plus changer entre le verdict et l'écriture. Tout est ensuite écrit dans un dossier de
		préparation, et rien n'est déplacé vers la destination tant que la dernière entrée n'est
		pas passée : un échec ne touche jamais aux fichiers que l'utilisateur avait déjà. Ce
		dossier vit dans la destination, donc sur le même disque, ce qui rend le déplacement
		final quasi instantané et la mesure d'espace libre juste.
		"""

		path = Path(path)
		destination = Path(destination)
		created_destination = not destination.exists()
		destination.mkdir(parents=True, exist_ok=True)
		workdir = Path(tempfile.mkdtemp(prefix=".zipguard-", dir=destination))
		committed = False

		try:
			snapshot = workdir / "archive"
			shutil.copyfile(path, snapshot)

			verdict = self.inspect(snapshot, name=path.name)
			if not verdict.safe:
				raise ExtractionRefused("Extraction refusée : " + " ".join(verdict.reasons))

			staging = workdir / "arbre"
			staging.mkdir()
			with open_archive(snapshot, read_cap=self.limits.max_total_bytes) as handle:
				planned = self._preflight(handle, destination, allow_links)
				written = self._stage(handle, planned, staging)

			self._commit(staging, destination)
			committed = True
			return written
		finally:
			shutil.rmtree(workdir, ignore_errors=True)
			if created_destination and not committed:
				with contextlib.suppress(OSError):  # ne retire que si rien d'autre n'y est
					destination.rmdir()

	def _preflight(
		self,
		handle: Archive,
		destination: Path,
		allow_links: bool,
	) -> list[_Planned]:
		"""
		Description: Valide tous les chemins, liens, doublons et la place disponible avant d'écrire.
		Usage: interne à safe_extract.
		Inputs: handle (Archive) archive ouverte, destination (Path) racine autorisée, allow_links (bool).
		Outputs: list[_Planned] des entrées validées, dans l'ordre de l'archive.

		Tout refus arrive ici, donc avant la moindre écriture : une archive piégée ne laisse
		aucune trace sur le disque.
		"""

		free = shutil.disk_usage(destination).free
		if free < self.limits.min_free_bytes:
			raise QuotaExceeded(
				f"Espace libre insuffisant : {human_bytes(free)} disponibles, "
				f"{human_bytes(self.limits.min_free_bytes)} exigés."
			)

		root = destination.resolve()
		seen: dict[tuple[str, ...], str] = {}
		parents: set[tuple[str, ...]] = set()
		planned: list[_Planned] = []

		for entry in handle.entries():
			self._resolve(destination, entry.name)
			parts = self._entry_parts(entry.name)
			if not parts:
				if entry.is_dir:
					continue
				raise ExtractionRefused(f"Entrée sans nom refusée : {entry.name!r}")

			kind, target = "dir" if entry.is_dir else "file", ""
			if entry.is_link:
				kind, target = "link", self._link_target(handle, entry, allow_links)

			self._check_layout(entry.name, parts, kind, seen, parents)
			self._check_existing(entry.name, root, parts, kind)
			planned.append(_Planned(entry, parts, kind, target))

		return planned

	@staticmethod
	def _link_target(handle: Archive, entry: Entry, allow_links: bool) -> str:
		"""
		Description: Décide si un lien peut être recréé, et rend sa cible validée.
		Usage: interne à _preflight.
		Inputs: handle (Archive), entry (Entry) entrée marquée is_link, allow_links (bool).
		Outputs: str cible relative, descendante, sans remontée.

		La règle est volontairement plus stricte que « reste dans le dossier » : une cible
		ne peut que descendre. Sans « .. » ni chemin absolu, aucune chaîne de liens, si
		tordue soit elle, ne peut ressortir de l'arborescence extraite.
		"""

		if not allow_links:
			raise ExtractionRefused(
				f"Lien refusé : {entry.name} pointe hors de l'archive et pourrait rediriger une écriture."
			)
		if entry.is_hardlink:
			raise ExtractionRefused(f"Lien physique refusé : {entry.name}")

		try:
			target = handle.link_target(entry)
		except (*_READ_ERRORS, KeyError, UnicodeDecodeError) as error:
			raise ExtractionRefused(f"Cible de lien illisible : {entry.name} ({error})") from error

		cleaned = target.replace("\\", "/")
		head = cleaned.split("/", 1)[0]
		if (
			not cleaned
			or "\x00" in cleaned
			or cleaned.startswith("/")
			or ntpath.isabs(target)
			or ":" in head
			or ".." in cleaned.split("/")
		):
			raise ExtractionRefused(
				f"Lien refusé : {entry.name} -> {target} ne reste pas sous son propre dossier."
			)
		return target

	@staticmethod
	def _check_layout(
		name: str,
		parts: tuple[str, ...],
		kind: str,
		seen: dict[tuple[str, ...], str],
		parents: set[tuple[str, ...]],
	) -> None:
		"""
		Description: Refuse les doublons et les chemins qui servent à la fois de fichier et de dossier.
		Usage: interne à _preflight.
		Inputs: name (str) nom brut, parts (tuple) chemin normalisé, kind (str) dir, file ou link, seen et parents (enrichis sur place).
		Outputs: None, lève ExtractionRefused sur conflit.

		Deux entrées au même nom feraient écraser la première en silence : celle que
		l'inspection a vue n'est alors plus celle qui arrive sur le disque. Un lien ne peut
		pas non plus servir de dossier parent, sinon une écriture passerait à travers lui.
		"""

		previous = seen.get(parts)
		if previous is not None and not (previous == kind == "dir"):
			raise ExtractionRefused(f"Entrée en double refusée : {name}")
		if kind != "dir" and parts in parents:
			raise ExtractionRefused(f"{name} sert à la fois de fichier et de dossier.")

		for depth in range(1, len(parts)):
			prefix = parts[:depth]
			if seen.get(prefix, "dir") != "dir":
				raise ExtractionRefused(f"{name} passe à travers une entrée qui n'est pas un dossier.")
			parents.add(prefix)
		seen[parts] = kind

	@staticmethod
	def _check_existing(name: str, root: Path, parts: tuple[str, ...], kind: str) -> None:
		"""
		Description: Refuse une entrée qui entrerait en conflit avec ce qui existe déjà sur le disque.
		Usage: interne à _preflight.
		Inputs: name (str) nom brut, root (Path) destination résolue, parts (tuple) chemin normalisé, kind (str) dir, file ou link.
		Outputs: None, lève ExtractionRefused sur conflit.

		Remplacer un fichier existant est le comportement attendu d'une extraction ; remplacer
		un dossier entier par un fichier, ou l'inverse, ne l'est jamais. Le contrôle couvre
		aussi les dossiers parents, pour que le déplacement final ne bute sur rien.
		"""

		for depth in range(1, len(parts)):
			parent = root.joinpath(*parts[:depth])
			if (parent.exists() or parent.is_symlink()) and not parent.is_dir():
				raise ExtractionRefused(f"{name} : un fichier existe déjà à la place d'un dossier parent.")

		target = root.joinpath(*parts)
		if not (target.exists() or target.is_symlink()):
			return
		is_real_dir = target.is_dir() and not target.is_symlink()
		if kind == "dir" and not target.is_dir():
			raise ExtractionRefused(f"{name} : un fichier existe déjà à cet emplacement.")
		if kind != "dir" and is_real_dir:
			raise ExtractionRefused(f"{name} : un dossier existe déjà à cet emplacement.")

	def _stage(self, handle: Archive, planned: list[_Planned], staging: Path) -> int:
		"""
		Description: Écrit toutes les entrées validées dans le dossier de préparation.
		Usage: interne à safe_extract.
		Inputs: handle (Archive), planned (list[_Planned]), staging (Path) dossier de préparation.
		Outputs: int octets écrits au total.
		"""

		written = 0
		for item in planned:
			target = staging.joinpath(*item.parts)
			if item.kind == "dir":
				target.mkdir(parents=True, exist_ok=True)
				continue
			target.parent.mkdir(parents=True, exist_ok=True)
			if item.kind == "link":
				os.symlink(item.link_target, target)
				continue
			written += self._write_entry(handle, item.entry, target, written)
		return written

	@staticmethod
	def _commit(staging: Path, destination: Path) -> None:
		"""
		Description: Déplace l'arborescence préparée vers la destination, sans suivre aucun lien.
		Usage: interne à safe_extract, une fois toutes les entrées écrites.
		Inputs: staging (Path) dossier de préparation, destination (Path) dossier final.
		Outputs: None.
		"""

		for current, dirnames, filenames in os.walk(staging, followlinks=False):
			relative = Path(current).relative_to(staging)
			target_dir = destination / relative
			target_dir.mkdir(parents=True, exist_ok=True)

			for name in filenames:
				os.replace(Path(current) / name, target_dir / name)
			for name in list(dirnames):
				source = Path(current) / name
				if source.is_symlink():
					os.replace(source, target_dir / name)
					dirnames.remove(name)

	def _write_entry(self, handle: Archive, entry: Entry, target: Path, already: int) -> int:
		"""
		Description: Écrit une entrée par blocs en recomptant les octets et la place restante.
		Usage: interne à _stage.
		Inputs: handle (Archive), entry (Entry), target (Path), already (int) octets déjà écrits.
		Outputs: int octets écrits pour cette entrée.
		"""

		written = 0
		next_check = FREE_SPACE_CHECK_EVERY

		with handle.open(entry) as source, open(target, "wb") as sink:
			while True:
				chunk = source.read(CHUNK)
				if not chunk:
					break
				written += len(chunk)

				if written > self.limits.max_entry_bytes:
					raise QuotaExceeded(
						f"Entrée {entry.name} dépasse {human_bytes(self.limits.max_entry_bytes)} "
						"pendant l'extraction."
					)
				if already + written > self.limits.max_extract_bytes:
					raise QuotaExceeded(
						f"Quota d'extraction dépassé : "
						f"{human_bytes(already + written)} > "
						f"{human_bytes(self.limits.max_extract_bytes)}."
					)
				if written >= next_check:
					self._check_free_space(target.parent)
					next_check += FREE_SPACE_CHECK_EVERY

				sink.write(chunk)
		return written

	def _check_free_space(self, where: Path) -> None:
		"""
		Description: Vérifie que la marge de disque libre est toujours respectée.
		Usage: interne à _write_entry.
		Inputs: where (Path) dossier surveillé.
		Outputs: None, lève QuotaExceeded si la marge est franchie.
		"""

		free = shutil.disk_usage(where).free
		if free < self.limits.min_free_bytes:
			raise QuotaExceeded(f"Extraction arrêtée : il ne reste que {human_bytes(free)} sur le disque.")

	@staticmethod
	def _entry_parts(name: str) -> tuple[str, ...]:
		"""
		Description: Découpe un nom d'entrée en composants sûrs, ou refuse le nom.
		Usage: interne, partagé par _resolve et _preflight.
		Inputs: name (str) nom d'entrée brut.
		Outputs: tuple[str, ...] composants sans vide, sans point et sans remontée.
		"""

		cleaned = name.replace("\\", "/")
		head = cleaned.split("/", 1)[0]

		if cleaned.startswith("/") or ntpath.isabs(name) or ":" in head:
			raise ExtractionRefused(f"Chemin absolu refusé : {name}")
		if "\x00" in cleaned:
			raise ExtractionRefused(f"Caractère nul refusé dans le nom : {name!r}")

		parts = tuple(part for part in cleaned.split("/") if part not in ("", "."))
		if any(part == ".." for part in parts):
			raise ExtractionRefused(f"Remontée de dossier refusée : {name}")
		return parts

	@classmethod
	def _resolve(cls, destination: Path, name: str) -> Path:
		"""
		Description: Résout un nom d'entrée en interdisant toute sortie du dossier cible.
		Usage: interne, protège contre le path traversal (Zip Slip).
		Inputs: destination (Path) racine autorisée, name (str) nom d'entrée.
		Outputs: Path sûr contenu dans destination.

		Les trois pièges classiques sont traités avant la résolution : chemin absolu, lettre
		de lecteur Windows, et remontée par deux points. Le contrôle final sur le chemin
		résolu attrape ce que les règles auraient laissé passer, notamment un lien déjà
		présent dans la destination qui pointerait ailleurs.
		"""

		parts = cls._entry_parts(name)
		root = destination.resolve()
		resolved = (root / Path(*parts)).resolve() if parts else root
		if resolved != root and root not in resolved.parents:
			raise ExtractionRefused(f"Chemin d'entrée hors du dossier cible : {name}")
		return resolved
