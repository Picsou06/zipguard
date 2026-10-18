from __future__ import annotations

import bz2
import contextlib
import gzip
import io
import lzma
import shutil
import tarfile
import tempfile
import warnings
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from .sources import FileSource, Source, as_source

DEFAULT_READ_CAP = 1_000_000_000

_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"
_SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

_LINK_TARGET_MAX = 4096

TAR_KINDS = ("tar", "tar.gz", "tar.bz2", "tar.xz")
STREAM_KINDS = ("gz", "bz2", "xz")


class UnsupportedArchive(Exception):
	"""
	Description: Signale un fichier dont le format n'est pas pris en charge par ZipGuard.
	Usage: levée par open_archive sur un fichier qui n'est pas une archive connue.
	Inputs: message (str) décrivant le fichier refusé.
	Outputs: exception à récupérer par l'appelant.
	"""


class EncryptedArchive(Exception):
	"""
	Description: Signale une archive dont même la liste des entrées est chiffrée.
	Usage: levée à l'ouverture d'un 7z à en-têtes chiffrés.
	Inputs: message (str) description.
	Outputs: exception que le scanner traduit en verdict « chiffrée ».
	"""


class ReadCapExceeded(Exception):
	"""
	Description: Signale qu'une lecture a dépassé le plafond d'octets autorisé.
	Usage: levée pendant l'inventaire d'un tar ou d'un flux compressé trop gros.
	Inputs: cap (int) plafond atteint, read (int) octets lus avant la coupure.
	Outputs: exception portant les deux compteurs.

	C'est le cœur défensif des formats sans manifeste : on ne fait jamais confiance à une
	taille annoncée, on mesure en lisant, et on coupe dès que le seuil est franchi.
	"""

	def __init__(self, cap: int, read: int) -> None:
		super().__init__(f"Lecture coupée à {read} o, plafond de {cap} o dépassé.")
		self.cap = cap
		self.read = read


# Tout ce qui peut sortir d'une tentative de lecture d'une entrée hostile ou abimée. Une
# archive trafiquée doit produire un verdict, jamais une trace d'exception.
SNIFF_ERRORS = (
	OSError,
	EOFError,
	KeyError,
	ValueError,
	ReadCapExceeded,
	tarfile.TarError,
	zipfile.BadZipFile,
)


@dataclass(frozen=True)
class Entry:
	"""
	Description: Entrée d'archive normalisée, commune à tous les formats pris en charge.
	Usage: for entry in archive.entries(): print(entry.name, entry.size).
	Inputs: name (str), size (int) octets décompressés, compressed_size (int) 0 si inconnu, is_dir (bool), is_link (bool), is_hardlink (bool), link_target (str) cible d'un lien tar, is_encrypted (bool).
	Outputs: structure immuable comparable d'un format à l'autre.

	is_link couvre les liens symboliques comme les liens physiques ; is_hardlink distingue
	les seconds, qui ne sont jamais extraits. La cible d'un lien zip vit dans le contenu de
	l'entrée et se lit avec Archive.link_target.
	"""

	name: str
	size: int
	compressed_size: int
	is_dir: bool = False
	is_link: bool = False
	is_hardlink: bool = False
	link_target: str = ""
	is_encrypted: bool = False

	@property
	def ratio(self) -> float:
		"""
		Description: Ratio de compression de l'entrée, 0 quand la taille compressée est inconnue.
		Usage: entry.ratio.
		Inputs: aucun.
		Outputs: float ratio décompressé/compressé.
		"""

		if self.compressed_size <= 0:
			return 0.0
		return self.size / self.compressed_size


class _CappedReader(io.RawIOBase):
	"""
	Description: Enveloppe un flux binaire en comptant les octets lus et coupe au plafond.
	Usage: tarfile.open(fileobj=_CappedReader(stream, cap), mode="r|").
	Inputs: raw (IO[bytes]) flux source, cap (int) plafond d'octets.
	Outputs: objet fichier lisible qui lève ReadCapExceeded au dépassement.
	"""

	def __init__(self, raw: IO[bytes], cap: int) -> None:
		super().__init__()
		self._raw = raw
		self._cap = cap
		self.read_bytes = 0

	def readable(self) -> bool:
		return True

	def read(self, size: int = -1) -> bytes:
		chunk = self._raw.read(size)
		self.read_bytes += len(chunk)
		if self.read_bytes > self._cap:
			raise ReadCapExceeded(self._cap, self.read_bytes)
		return chunk

	def readinto(self, buffer) -> int:  # pragma: no cover - utilisé par io.BufferedReader
		chunk = self.read(len(buffer))
		buffer[: len(chunk)] = chunk
		return len(chunk)

	def close(self) -> None:
		try:
			self._raw.close()
		finally:
			super().close()


class _Owning(io.RawIOBase):
	"""
	Description: Flux de décompression qui referme aussi le flux brut qu'il lit.
	Usage: interne à _open_codec.
	Inputs: stream (IO[bytes]) flux décompressé, raw (IO[bytes]) flux brut sous jacent.
	Outputs: objet fichier lisible ; le refermer referme les deux.

	gzip, bz2 et lzma ne referment pas un objet fichier qu'on leur a confié : sans cette
	enveloppe, chaque lecture d'une archive distante laisserait une connexion ouverte.
	"""

	def __init__(self, stream: IO[bytes], raw: IO[bytes]) -> None:
		super().__init__()
		self._stream = stream
		self._raw = raw

	def readable(self) -> bool:
		return True

	def read(self, size: int = -1) -> bytes:
		return self._stream.read(size)

	def readinto(self, buffer) -> int:  # pragma: no cover - utilisé par io.BufferedReader
		chunk = self.read(len(buffer))
		buffer[: len(chunk)] = chunk
		return len(chunk)

	def close(self) -> None:
		try:
			self._stream.close()
		finally:
			try:
				self._raw.close()
			finally:
				super().close()


def _open_codec(source: Source, codec: str) -> IO[bytes]:
	"""
	Description: Ouvre une source et la décompresse au vol selon le codec demandé.
	Usage: _open_codec(source, "gz").
	Inputs: source (Source) archive, codec (str) gz, bz2, xz, ou none pour le flux brut.
	Outputs: objet fichier binaire décompressé, à refermer par l'appelant.
	"""

	raw = source.open()
	if codec == "none":
		return raw
	try:
		if codec == "gz":
			stream: IO[bytes] = gzip.GzipFile(fileobj=raw, mode="rb")
		elif codec == "bz2":
			stream = bz2.BZ2File(raw)
		else:
			stream = lzma.LZMAFile(raw)
	except BaseException:
		raw.close()
		raise
	return _Owning(stream, raw)


def _head(source: Source, size: int = 1024) -> bytes:
	"""
	Description: Lit les premiers octets d'une source pour reconnaître sa signature.
	Usage: _head(FileSource(Path("a.zip"))).
	Inputs: source (Source) archive à renifler, size (int) nombre d'octets à lire.
	Outputs: bytes lus, éventuellement plus courts que demandé.
	"""

	with source.open() as handle:
		return handle.read(size)


def _looks_like_tar(blob: bytes) -> bool:
	"""
	Description: Dit si un bloc de 512 octets porte la signature d'un en-tête tar.
	Usage: _looks_like_tar(first_block).
	Inputs: blob (bytes) début du flux décompressé.
	Outputs: bool vrai si la signature ustar est présente.
	"""

	return blob[_TAR_MAGIC_OFFSET : _TAR_MAGIC_OFFSET + len(_TAR_MAGIC)] == _TAR_MAGIC


def _peek_decompressed(source: Source, codec: str, size: int = 512) -> bytes:
	"""
	Description: Décompresse un tout petit morceau d'un flux pour voir ce qu'il contient.
	Usage: _peek_decompressed(source, "gz").
	Inputs: source (Source) archive compressée, codec (str) gz, bz2 ou xz, size (int) octets voulus.
	Outputs: bytes décompressés, vides si le flux est illisible.

	La lecture est volontairement minuscule : reconnaître un format ne doit jamais coûter
	une décompression complète.
	"""

	try:
		with _open_codec(source, codec) as stream:
			return stream.read(size)
	except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError):
		return b""


def sniff_kind(blob: bytes) -> str | None:
	"""
	Description: Reconnaît un format à partir des premiers octets seulement, sans toucher au disque.
	Usage: sniff_kind(handle.head(entry)).
	Inputs: blob (bytes) début du fichier, idéalement au moins 512 octets.
	Outputs: str parmi zip, tar, gz, bz2, xz, 7z, ou None.

	Volontairement sommaire : un flux gzip est annoncé gz même s'il contient un tar, car
	trancher demanderait de décompresser. C'est suffisant pour décider s'il faut descendre
	d'un niveau, et detect_kind affine ensuite sur le fichier réel.
	"""

	if not blob:
		return None
	if blob.startswith(_SEVENZIP_MAGIC):
		return "7z"
	if blob.startswith(_ZIP_MAGICS):
		return "zip"
	if _looks_like_tar(blob):
		return "tar"
	if blob.startswith(b"\x1f\x8b"):
		return "gz"
	if blob.startswith(b"BZh"):
		return "bz2"
	if blob.startswith(b"\xfd7zXZ\x00"):
		return "xz"
	return None


def detect_kind(target: Source | Path) -> str | None:
	"""
	Description: Reconnaît le format d'une archive par sa signature, jamais par son extension.
	Usage: detect_kind(Path("suspect.bin")).
	Inputs: target (Source | Path) archive à examiner.
	Outputs: str parmi zip, tar, tar.gz, tar.bz2, tar.xz, gz, bz2, xz, 7z, ou None.

	Une archive renommée en .txt reste une archive : se fier à l'extension serait le premier
	trou dans la défense.
	"""

	source = as_source(target)
	if not source.exists():
		return None

	head = _head(source)
	kind = sniff_kind(head)

	if kind is None:
		if not source.seekable:
			return None
		with source.open() as stream:
			return "zip" if zipfile.is_zipfile(stream) else None
	if kind in STREAM_KINDS:
		return f"tar.{kind}" if _looks_like_tar(_peek_decompressed(source, kind)) else kind
	return kind


class Archive:
	"""
	Description: Interface commune d'inspection, identique quel que soit le format d'archive.
	Usage: with open_archive(path) as handle: handle.entries().
	Inputs: source (Source) origine des octets, kind (str) format détecté, read_cap (int) plafond de lecture, memory_cap (int | None) plafond d'une entrée tenue en mémoire.
	Outputs: objet exposant entries(), open() et compressed_total.
	"""

	def __init__(
		self,
		source: Source,
		kind: str,
		read_cap: int = DEFAULT_READ_CAP,
		memory_cap: int | None = None,
	) -> None:
		self.source = source
		self.kind = kind
		self.read_cap = read_cap
		self.memory_cap = read_cap if memory_cap is None else min(read_cap, memory_cap)
		# Entrées qu'un plafond a empêché de renifler : le scanner ne peut pas savoir si ce
		# sont des archives, donc il doit les compter comme invérifiables.
		self.unsniffable: list[str] = []
		self._entries: list[Entry] | None = None
		self._measured = False

	@property
	def compressed_total(self) -> int:
		"""
		Description: Taille compressée de référence pour le calcul du ratio global.
		Usage: handle.compressed_total.
		Inputs: aucun.
		Outputs: int octets, au minimum 1 pour éviter une division par zéro.
		"""

		return max(1, self.source.size())

	@property
	def sizes_are_measured(self) -> bool:
		"""
		Description: Dit si les tailles proviennent d'une lecture réelle plutôt que d'un manifeste.
		Usage: handle.sizes_are_measured.
		Inputs: aucun.
		Outputs: bool vrai pour tar et flux compressés, faux pour zip et 7z.
		"""

		return self._measured

	def entries(self) -> list[Entry]:
		"""
		Description: Inventorie les entrées de l'archive, en mémorisant le résultat.
		Usage: handle.entries().
		Inputs: aucun.
		Outputs: list[Entry] décrivant chaque entrée.
		"""

		if self._entries is None:
			self._entries = self._read_entries()
		return self._entries

	def open(self, entry: Entry) -> IO[bytes]:
		"""
		Description: Ouvre une entrée en lecture binaire sans la décompresser entièrement.
		Usage: with handle.open(entry) as stream: stream.read(4096).
		Inputs: entry (Entry) entrée à lire.
		Outputs: objet fichier binaire à refermer par l'appelant.
		"""

		raise NotImplementedError

	def head(self, entry: Entry, size: int = 1024) -> bytes:
		"""
		Description: Lit les tout premiers octets d'une entrée pour reconnaître son format.
		Usage: sniff_kind(handle.head(entry)).
		Inputs: entry (Entry) entrée à renifler, size (int) nombre d'octets voulus.
		Outputs: bytes lus, vides si l'entrée est illisible ou sans contenu.

		Une entrée illisible n'est pas une erreur ici : c'est juste une entrée dont on ne
		saura pas si elle cache une archive, et l'inspection le signalera autrement. Une
		archive trafiquée doit produire un verdict, jamais une trace d'exception : pour un
		outil défensif, planter sur l'entrée hostile est le pire mode de défaillance.
		"""

		if entry.is_dir or entry.is_link or entry.is_encrypted or entry.size <= 0:
			return b""
		try:
			stream = self.open(entry)
		except ReadCapExceeded:
			self.unsniffable.append(entry.name)
			return b""
		except SNIFF_ERRORS:
			return b""
		try:
			return stream.read(size)
		except SNIFF_ERRORS:
			return b""
		finally:
			with contextlib.suppress(Exception):
				stream.close()

	def link_target(self, entry: Entry) -> str:
		"""
		Description: Rend la cible d'un lien symbolique, telle qu'elle est écrite dans l'archive.
		Usage: handle.link_target(entry).
		Inputs: entry (Entry) entrée marquée is_link.
		Outputs: str cible brute, à valider par l'appelant avant tout usage.
		"""

		return entry.link_target

	def close(self) -> None:
		"""
		Description: Libère les ressources ouvertes par l'adaptateur.
		Usage: handle.close(), ou le gestionnaire de contexte.
		Inputs: aucun.
		Outputs: None.
		"""

	def _read_entries(self) -> list[Entry]:
		raise NotImplementedError

	def __enter__(self) -> Archive:
		return self

	def __exit__(self, *exc_info: object) -> None:
		self.close()


class ZipArchive(Archive):
	"""
	Description: Adaptateur ZIP, le seul format qui publie un manifeste complet et vérifiable.
	Usage: open_archive(Path("a.zip")).
	Inputs: identiques à Archive.
	Outputs: entrées issues du répertoire central du ZIP.
	"""

	def __init__(
		self,
		source: Source,
		kind: str,
		read_cap: int = DEFAULT_READ_CAP,
		memory_cap: int | None = None,
	) -> None:
		super().__init__(source, kind, read_cap, memory_cap)
		self._raw = source.open()
		try:
			self._zip = zipfile.ZipFile(self._raw)
		except BaseException:
			self._raw.close()
			raise

	@property
	def compressed_total(self) -> int:
		"""
		Description: Taille compressée de référence, plafonnée par la taille réelle du fichier.
		Usage: handle.compressed_total.
		Inputs: aucun.
		Outputs: int octets, au minimum 1.

		Prendre la somme des tailles compressées annoncées serait naïf : dans une bombe à
		entrées recouvrantes, plusieurs entrées du répertoire central pointent vers le même
		bloc compressé, donc cette somme est gonflée autant de fois qu'il y a de références
		et le ratio s'en trouve divisé d'autant. La taille du fichier sur le disque, elle,
		ne ment pas. On garde la plus petite des deux.
		"""

		declared = sum(info.compress_size for info in self._zip.infolist())
		real = self.source.size()
		return max(1, min(declared, real) if declared else real)

	@staticmethod
	def _is_symlink(info: zipfile.ZipInfo) -> bool:
		"""
		Description: Repère un lien symbolique encodé dans les attributs externes d'une entrée ZIP.
		Usage: ZipArchive._is_symlink(info).
		Inputs: info (ZipInfo) métadonnées de l'entrée.
		Outputs: bool vrai si les bits de mode Unix décrivent un lien.
		"""

		return (info.external_attr >> 16) & 0o170000 == 0o120000

	def _read_entries(self) -> list[Entry]:
		return [
			Entry(
				name=info.filename,
				size=info.file_size,
				compressed_size=info.compress_size,
				is_dir=info.is_dir(),
				is_link=self._is_symlink(info),
				# Le bit 0 des drapeaux couvre le chiffrement historique comme AES.
				is_encrypted=bool(info.flag_bits & 0x1),
			)
			for info in self._zip.infolist()
		]

	def open(self, entry: Entry) -> IO[bytes]:
		"""
		Description: Ouvre une entrée ZIP en lecture, sans laisser zipfile écrire sur la sortie.
		Usage: with handle.open(entry) as stream: stream.read(4096).
		Inputs: entry (Entry) entrée à lire.
		Outputs: objet fichier binaire à refermer par l'appelant.

		zipfile émet un avertissement quand plusieurs entrées se recouvrent. Le signal est
		juste, mais ZipGuard le traite déjà par le ratio calculé contre la taille réelle du
		fichier : le laisser remonter ne ferait que barbouiller le rapport d'une ligne que
		l'utilisateur n'a pas demandée, au milieu du verdict.
		"""

		with warnings.catch_warnings():
			warnings.simplefilter("ignore", UserWarning)
			return self._zip.open(entry.name)

	def link_target(self, entry: Entry) -> str:
		"""
		Description: Lit la cible d'un lien zip, stockée comme contenu de l'entrée.
		Usage: handle.link_target(entry).
		Inputs: entry (Entry) entrée marquée is_link.
		Outputs: str cible décodée en UTF-8.

		La lecture est plafonnée : une cible plus longue qu'un chemin raisonnable n'en est
		pas une, et lève ValueError plutôt que d'être lue en entier.
		"""

		with self.open(entry) as stream:
			raw = stream.read(_LINK_TARGET_MAX + 1)
		if len(raw) > _LINK_TARGET_MAX:
			raise ValueError(f"Cible de lien trop longue : {entry.name}")
		return raw.decode("utf-8")

	def close(self) -> None:
		try:
			self._zip.close()
		finally:
			self._raw.close()


class TarArchive(Archive):
	"""
	Description: Adaptateur tar, avec ou sans compression, inventorié derrière un plafond de lecture.
	Usage: open_archive(Path("a.tar.gz"), read_cap=...).
	Inputs: identiques à Archive.
	Outputs: entrées mesurées en parcourant le flux une seule fois.

	Un tar ne publie pas de taille compressée par entrée et lister ses membres impose de
	traverser le flux décompressé : ZipGuard le lit derrière un compteur qui coupe au seuil,
	ce qui transforme l'inventaire lui même en garde fou.
	"""

	def __init__(
		self,
		source: Source,
		kind: str,
		read_cap: int = DEFAULT_READ_CAP,
		memory_cap: int | None = None,
	) -> None:
		super().__init__(source, kind, read_cap, memory_cap)
		self._measured = True
		self._open_streams: list[IO[bytes]] = []
		self._heads: dict[str, bytes] = {}

	@property
	def _codec(self) -> str:
		return self.kind.partition(".")[2] or "none"

	def _stream(self) -> _CappedReader:
		return _CappedReader(_open_codec(self.source, self._codec), self.read_cap)

	def _read_entries(self) -> list[Entry]:
		entries: list[Entry] = []
		reader = self._stream()
		try:
			with tarfile.open(fileobj=reader, mode="r|") as archive:  # type: ignore[arg-type]
				for member in archive:
					entries.append(
						Entry(
							name=member.name,
							size=member.size if member.isfile() else 0,
							compressed_size=0,
							is_dir=member.isdir(),
							is_link=member.issym() or member.islnk(),
							is_hardlink=member.islnk(),
							link_target=member.linkname if member.issym() else "",
						)
					)
					if member.isfile() and member.size:
						extracted = archive.extractfile(member)
						if extracted is not None:
							self._heads[member.name] = extracted.read(1024)
		finally:
			reader.close()
		return entries

	def head(self, entry: Entry, size: int = 1024) -> bytes:
		"""
		Description: Rend les premiers octets d'une entrée, relevés pendant l'unique parcours du flux.
		Usage: handle.head(entry).
		Inputs: entry (Entry) entrée concernée, size (int) nombre d'octets voulus.
		Outputs: bytes mis en cache lors de l'inventaire.

		Un tar compressé ne se parcourt que séquentiellement : rouvrir le flux pour chaque
		entrée coûterait un temps quadratique, donc l'inventaire relève les en têtes au vol.
		"""

		if self._entries is None:
			self.entries()
		return self._heads.get(entry.name, b"")[:size]

	def open(self, entry: Entry) -> IO[bytes]:
		reader = self._stream()
		archive = tarfile.open(fileobj=reader, mode="r|")  # type: ignore[arg-type]
		for member in archive:
			if member.name == entry.name:
				extracted = archive.extractfile(member)
				if extracted is None:
					break
				self._open_streams.extend((extracted, reader))
				return extracted
		archive.close()
		reader.close()
		raise KeyError(f"Entrée introuvable dans l'archive : {entry.name}")

	def close(self) -> None:
		for stream in self._open_streams:
			with contextlib.suppress(Exception):  # fermeture best effort
				stream.close()
		self._open_streams.clear()


class StreamArchive(Archive):
	"""
	Description: Adaptateur des flux compressés simples (.gz, .bz2, .xz) qui ne contiennent qu'un fichier.
	Usage: open_archive(Path("gros.txt.gz")).
	Inputs: identiques à Archive.
	Outputs: une entrée unique dont la taille est mesurée, jamais déclarée.

	Le pied de page gzip annonce une taille modulo 4 Gio, donc mensongère par construction
	au delà : la seule valeur digne de confiance est celle que l'on compte soi même.
	"""

	def __init__(
		self,
		source: Source,
		kind: str,
		read_cap: int = DEFAULT_READ_CAP,
		memory_cap: int | None = None,
	) -> None:
		super().__init__(source, kind, read_cap, memory_cap)
		self._measured = True

	def _raw_stream(self) -> IO[bytes]:
		return _open_codec(self.source, self.kind)

	@property
	def _inner_name(self) -> str:
		name = self.source.name
		suffix = f".{self.kind}"
		return name[: -len(suffix)] if name.endswith(suffix) else f"{name}.decompresse"

	def _read_entries(self) -> list[Entry]:
		reader = _CappedReader(self._raw_stream(), self.read_cap)
		measured = 0
		try:
			while True:
				chunk = reader.read(65536)
				if not chunk:
					break
				measured += len(chunk)
		finally:
			reader.close()
		return [
			Entry(
				name=self._inner_name,
				size=measured,
				compressed_size=self.source.size(),
			)
		]

	def open(self, entry: Entry) -> IO[bytes]:
		return self._raw_stream()


class SevenZipArchive(Archive):
	"""
	Description: Adaptateur 7z, actif seulement quand la dépendance optionnelle py7zr est installée.
	Usage: pip install "zipguard[7z]" puis open_archive(Path("a.7z")).
	Inputs: identiques à Archive.
	Outputs: entrées issues du manifeste 7z.

	Limite de confiance à connaître : py7zr ne sait pas rendre une entrée sous forme de flux
	borné. Pour une source sur disque, lire une entrée passe par un dossier temporaire
	privé ; pour une source sans disque (archive distante, archive imbriquée lue en
	mémoire), l'entrée est décompressée dans un tampon mémoire plafonné. Dans les deux cas
	la taille annoncée est vérifiée avant, et la taille réelle après : un manifeste menteur
	est détecté, mais seulement une fois l'entrée décompressée. L'exposition est bornée à
	une entrée à la fois. Les autres formats n'ont pas ce détour, parce qu'ils savent se
	lire par blocs.
	"""

	def __init__(
		self,
		source: Source,
		kind: str,
		read_cap: int = DEFAULT_READ_CAP,
		memory_cap: int | None = None,
	) -> None:
		super().__init__(source, kind, read_cap, memory_cap)
		try:
			import py7zr
		except ImportError as error:  # pragma: no cover - dépend de l'environnement
			raise UnsupportedArchive(
				'Archive 7z détectée : installe la dépendance optionnelle avec pip install "zipguard[7z]".'
			) from error
		self._py7zr = py7zr
		self._raw = None if isinstance(source, FileSource) else source.open()
		try:
			target = source.path if isinstance(source, FileSource) else self._raw
			self._archive = py7zr.SevenZipFile(target, mode="r")
		except py7zr.exceptions.PasswordRequired as error:
			self._close_raw()
			raise EncryptedArchive(
				"Archive 7z à en-têtes chiffrés : même la liste des entrées est illisible."
			) from error
		except BaseException:
			self._close_raw()
			raise
		self._encrypted = bool(self._archive.needs_password())
		self._workdirs: list[Path] = []

	def _close_raw(self) -> None:
		if self._raw is not None:
			self._raw.close()

	def _read_entries(self) -> list[Entry]:
		entries: list[Entry] = []
		for info in self._archive.list():
			is_dir = bool(getattr(info, "is_directory", False))
			entries.append(
				Entry(
					name=info.filename,
					size=int(getattr(info, "uncompressed", 0) or 0),
					compressed_size=int(getattr(info, "compressed", 0) or 0),
					is_dir=is_dir,
					is_link=bool(getattr(info, "is_symlink", False)),
					is_encrypted=self._encrypted and not is_dir,
				)
			)
		return entries

	def open(self, entry: Entry) -> IO[bytes]:
		if entry.size > self.read_cap:
			raise ReadCapExceeded(self.read_cap, entry.size)
		if self.source.on_disk:
			return self._open_on_disk(entry)
		return self._open_in_memory(entry)

	def _extract(self, entry: Entry, **options) -> None:
		self._archive.reset()
		try:
			self._archive.extract(targets=[entry.name], **options)
		except self._py7zr.exceptions.ArchiveError as error:
			# py7zr a ses propres exceptions : on les ramène à une erreur de lecture connue
			# pour qu'une entrée trafiquée produise un verdict et non une trace.
			raise ValueError(f"Entrée 7z illisible : {error}") from error

	def _open_on_disk(self, entry: Entry) -> IO[bytes]:
		workdir = Path(tempfile.mkdtemp(prefix="zipguard-7z-"))
		self._workdirs.append(workdir)
		self._extract(entry, path=workdir)

		extracted = workdir / entry.name
		if not extracted.is_file():
			found = [candidate for candidate in workdir.rglob("*") if candidate.is_file()]
			if not found:
				raise KeyError(f"Entrée introuvable dans l'archive : {entry.name}")
			extracted = found[0]

		actual = extracted.stat().st_size
		if actual > self.read_cap:
			raise ReadCapExceeded(self.read_cap, actual)

		return open(extracted, "rb")

	def _open_in_memory(self, entry: Entry) -> IO[bytes]:
		# Le tampon de py7zr ignore en silence ce qui dépasse sa limite : on lui donne un
		# octet de marge, et un tampon plein jusqu'à elle signe une entrée trop grosse. La
		# limite est celle de la mémoire, plus serrée que le plafond de lecture.
		if entry.size > self.memory_cap:
			raise ReadCapExceeded(self.memory_cap, entry.size)
		factory = self._py7zr.io.BytesIOFactory(self.memory_cap + 1)
		self._extract(entry, factory=factory)
		try:
			product = factory.get(entry.name)
		except KeyError as error:
			raise KeyError(f"Entrée introuvable dans l'archive : {entry.name}") from error

		actual = product.size()
		if actual > self.memory_cap:
			raise ReadCapExceeded(self.memory_cap, actual)
		product.seek(0)
		return io.BytesIO(product.read())

	def close(self) -> None:
		try:
			self._archive.close()
		finally:
			self._close_raw()
			for workdir in self._workdirs:
				shutil.rmtree(workdir, ignore_errors=True)
			self._workdirs.clear()


def open_archive(
	target: Source | Path,
	read_cap: int = DEFAULT_READ_CAP,
	memory_cap: int | None = None,
) -> Archive:
	"""
	Description: Ouvre n'importe quelle archive prise en charge derrière une interface unique.
	Usage: with open_archive(Path("a.tar.gz"), read_cap=1_000_000) as handle: handle.entries().
	Inputs: target (Source | Path) archive, read_cap (int) plafond d'octets décompressés lus, memory_cap (int | None) plafond d'une entrée décompressée en mémoire.
	Outputs: Archive adaptée au format détecté.

	Lève UnsupportedArchive quand la signature n'est reconnue par aucun adaptateur, et
	EncryptedArchive quand le format chiffre jusqu'à sa liste d'entrées.
	"""

	source = as_source(target)
	kind = detect_kind(source)
	if kind is None:
		raise UnsupportedArchive(f"Format non reconnu ou fichier illisible : {source.name}")

	if kind in ("zip", "7z") and not source.seekable:
		raise UnsupportedArchive(
			f"Archive {kind} illisible en flux continu : son manifeste est en fin de fichier "
			"et le serveur ne permet pas la lecture par plages."
		)

	if kind == "zip":
		return ZipArchive(source, kind, read_cap, memory_cap)
	if kind in TAR_KINDS:
		return TarArchive(source, kind, read_cap, memory_cap)
	if kind in STREAM_KINDS:
		return StreamArchive(source, kind, read_cap, memory_cap)
	if kind == "7z":
		return SevenZipArchive(source, kind, read_cap, memory_cap)

	raise UnsupportedArchive(f"Format non pris en charge : {kind}")  # pragma: no cover


def supported_kinds() -> Iterator[str]:
	"""
	Description: Énumère les formats que ZipGuard sait inspecter.
	Usage: list(supported_kinds()).
	Inputs: aucun.
	Outputs: Iterator[str] des identifiants de format.
	"""

	yield "zip"
	yield from TAR_KINDS
	yield from STREAM_KINDS
	yield "7z"
