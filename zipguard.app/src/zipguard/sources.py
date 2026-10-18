from __future__ import annotations

import io
from pathlib import Path
from typing import IO


class Source:
	"""
	Description: Origine des octets d'une archive : fichier local, mémoire ou serveur distant.
	Usage: with source.open() as stream: stream.read(4096).
	Inputs: aucun, la classe est abstraite.
	Outputs: interface commune lue par tous les adaptateurs de format.

	Les adaptateurs ne parlent jamais au disque directement : ils demandent un flux à leur
	source. C'est ce qui permet d'inspecter une archive distante sans la poser sur le disque,
	avec exactement le même code que pour un fichier local.

	on_disk dit si l'inspection a le droit d'écrire des fichiers temporaires pour les
	archives imbriquées ; seekable dit si le flux rendu par open() sait se déplacer, ce
	qu'exigent zip et 7z, qui lisent leur manifeste en fin de fichier.
	"""

	name: str = ""
	on_disk: bool = False
	seekable: bool = True

	def size(self) -> int:
		"""
		Description: Taille en octets de l'archive telle qu'elle est stockée, donc compressée.
		Usage: source.size().
		Inputs: aucun.
		Outputs: int octets.
		"""

		raise NotImplementedError

	def open(self) -> IO[bytes]:
		"""
		Description: Ouvre un nouveau flux binaire positionné au début de l'archive.
		Usage: with source.open() as stream: ...
		Inputs: aucun.
		Outputs: objet fichier binaire à refermer par l'appelant.
		"""

		raise NotImplementedError

	def exists(self) -> bool:
		"""
		Description: Dit si la source peut être lue.
		Usage: source.exists().
		Inputs: aucun.
		Outputs: bool.
		"""

		return True

	def __repr__(self) -> str:
		return f"{type(self).__name__}({self.name!r})"


class FileSource(Source):
	"""
	Description: Archive posée sur le disque local.
	Usage: FileSource(Path("a.zip")).
	Inputs: path (Path) chemin du fichier.
	Outputs: source lisible et déplaçable, autorisée à utiliser des fichiers temporaires.
	"""

	on_disk = True

	def __init__(self, path: Path) -> None:
		self.path = Path(path)
		self.name = self.path.name

	def size(self) -> int:
		return self.path.stat().st_size

	def open(self) -> IO[bytes]:
		return open(self.path, "rb")

	def exists(self) -> bool:
		return self.path.is_file()


class MemorySource(Source):
	"""
	Description: Archive tenue en mémoire, typiquement une archive imbriquée lue sans disque.
	Usage: MemorySource(b"PK...", "fille.zip").
	Inputs: data (bytes) contenu, name (str) nom affiché.
	Outputs: source lisible et déplaçable, qui n'écrit jamais sur le disque.
	"""

	def __init__(self, data: bytes, name: str) -> None:
		self._data = data
		self.name = name

	def size(self) -> int:
		return len(self._data)

	def open(self) -> IO[bytes]:
		return io.BytesIO(self._data)


def as_source(target: Source | Path | str) -> Source:
	"""
	Description: Normalise un chemin ou une source déjà construite en Source.
	Usage: as_source(Path("a.zip")).
	Inputs: target (Source | Path | str) archive à lire ; une chaîne est un chemin local.
	Outputs: Source correspondante.

	Une URL n'est jamais devinée à partir d'une chaîne : lire le réseau doit être un choix
	explicite de l'appelant, via remote.RemoteSource.
	"""

	if isinstance(target, Source):
		return target
	return FileSource(Path(target))
