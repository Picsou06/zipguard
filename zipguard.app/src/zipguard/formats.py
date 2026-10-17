from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterator

DEFAULT_READ_CAP = 1_000_000_000

_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"
_SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

TAR_KINDS = ("tar", "tar.gz", "tar.bz2", "tar.xz")
STREAM_KINDS = ("gz", "bz2", "xz")


class UnsupportedArchive(Exception):
	"""
	Description: Signale un fichier dont le format n'est pas pris en charge par ZipGuard.
	Usage: levée par open_archive sur un fichier qui n'est pas une archive connue.
	Inputs: message (str) décrivant le fichier refusé.
	Outputs: exception à récupérer par l'appelant.
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


@dataclass(frozen=True)
class Entry:
	"""
	Description: Entrée d'archive normalisée, commune à tous les formats pris en charge.
	Usage: for entry in archive.entries(): print(entry.name, entry.size).
	Inputs: name (str), size (int) octets décompressés, compressed_size (int) 0 si inconnu, is_dir (bool).
	Outputs: structure immuable comparable d'un format à l'autre.
	"""

	name: str
	size: int
	compressed_size: int
	is_dir: bool = False
	is_link: bool = False

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


def _head(path: Path, size: int = 1024) -> bytes:
	"""
	Description: Lit les premiers octets d'un fichier pour reconnaître sa signature.
	Usage: _head(Path("a.zip")).
	Inputs: path (Path) fichier à renifler, size (int) nombre d'octets à lire.
	Outputs: bytes lus, éventuellement plus courts que demandé.
	"""

	with open(path, "rb") as handle:
		return handle.read(size)


def _looks_like_tar(blob: bytes) -> bool:
	"""
	Description: Dit si un bloc de 512 octets porte la signature d'un en-tête tar.
	Usage: _looks_like_tar(first_block).
	Inputs: blob (bytes) début du flux décompressé.
	Outputs: bool vrai si la signature ustar est présente.
	"""

	return blob[_TAR_MAGIC_OFFSET : _TAR_MAGIC_OFFSET + len(_TAR_MAGIC)] == _TAR_MAGIC


def _peek_decompressed(path: Path, codec: str, size: int = 512) -> bytes:
	"""
	Description: Décompresse un tout petit morceau d'un flux pour voir ce qu'il contient.
	Usage: _peek_decompressed(Path("a.tar.gz"), "gz").
	Inputs: path (Path) fichier compressé, codec (str) gz, bz2 ou xz, size (int) octets voulus.
	Outputs: bytes décompressés, vides si le flux est illisible.

	La lecture est volontairement minuscule : reconnaître un format ne doit jamais coûter
	une décompression complète.
	"""

	opener = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}[codec]
	try:
		with opener(path, "rb") as stream:  # type: ignore[operator]
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


def detect_kind(path: Path) -> str | None:
	"""
	Description: Reconnaît le format d'un fichier par sa signature, jamais par son extension.
	Usage: detect_kind(Path("suspect.bin")).
	Inputs: path (Path) fichier à examiner.
	Outputs: str parmi zip, tar, tar.gz, tar.bz2, tar.xz, gz, bz2, xz, 7z, ou None.

	Une archive renommée en .txt reste une archive : se fier à l'extension serait le premier
	trou dans la défense.
	"""

	path = Path(path)
	if not path.is_file():
		return None

	head = _head(path)
	kind = sniff_kind(head)

	if kind is None:
		return "zip" if zipfile.is_zipfile(path) else None
	if kind in STREAM_KINDS:
		return f"tar.{kind}" if _looks_like_tar(_peek_decompressed(path, kind)) else kind
	return kind


class Archive:
	"""
	Description: Interface commune d'inspection, identique quel que soit le format d'archive.
	Usage: with open_archive(path) as handle: handle.entries().
	Inputs: path (Path) archive, kind (str) format détecté, read_cap (int) plafond de lecture.
	Outputs: objet exposant entries(), open() et compressed_total.
	"""

	def __init__(self, path: Path, kind: str, read_cap: int = DEFAULT_READ_CAP) -> None:
		self.path = Path(path)
		self.kind = kind
		self.read_cap = read_cap
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

		return max(1, self.path.stat().st_size)

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
		saura pas si elle cache une archive, et l'inspection le signalera autrement.
		"""

		if entry.is_dir or entry.is_link or entry.size <= 0:
			return b""
		try:
			stream = self.open(entry)
		except (OSError, KeyError, ValueError, ReadCapExceeded):
			return b""
		try:
			return stream.read(size)
		except (OSError, ValueError, ReadCapExceeded):
			return b""
		finally:
			stream.close()

	def close(self) -> None:
		"""
		Description: Libère les ressources ouvertes par l'adaptateur.
		Usage: handle.close(), ou le gestionnaire de contexte.
		Inputs: aucun.
		Outputs: None.
		"""

	def _read_entries(self) -> list[Entry]:
		raise NotImplementedError

	def __enter__(self) -> "Archive":
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

	def __init__(self, path: Path, kind: str, read_cap: int = DEFAULT_READ_CAP) -> None:
		super().__init__(path, kind, read_cap)
		self._zip = zipfile.ZipFile(self.path)

	@property
	def compressed_total(self) -> int:
		total = sum(info.compress_size for info in self._zip.infolist())
		return max(1, total)

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
			)
			for info in self._zip.infolist()
		]

	def open(self, entry: Entry) -> IO[bytes]:
		return self._zip.open(entry.name)

	def close(self) -> None:
		self._zip.close()


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

	def __init__(self, path: Path, kind: str, read_cap: int = DEFAULT_READ_CAP) -> None:
		super().__init__(path, kind, read_cap)
		self._measured = True
		self._open_streams: list[IO[bytes]] = []
		self._heads: dict[str, bytes] = {}

	@property
	def _codec(self) -> str:
		return self.kind.partition(".")[2] or "none"

	def _stream(self) -> _CappedReader:
		openers = {
			"gz": lambda: gzip.open(self.path, "rb"),
			"bz2": lambda: bz2.open(self.path, "rb"),
			"xz": lambda: lzma.open(self.path, "rb"),
			"none": lambda: open(self.path, "rb"),
		}
		return _CappedReader(openers[self._codec](), self.read_cap)

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
				self._open_streams.append(extracted)
				return extracted
		archive.close()
		reader.close()
		raise KeyError(f"Entrée introuvable dans l'archive : {entry.name}")

	def close(self) -> None:
		for stream in self._open_streams:
			try:
				stream.close()
			except Exception:  # pragma: no cover - fermeture best effort
				pass
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

	def __init__(self, path: Path, kind: str, read_cap: int = DEFAULT_READ_CAP) -> None:
		super().__init__(path, kind, read_cap)
		self._measured = True

	def _raw_stream(self) -> IO[bytes]:
		openers = {
			"gz": lambda: gzip.open(self.path, "rb"),
			"bz2": lambda: bz2.open(self.path, "rb"),
			"xz": lambda: lzma.open(self.path, "rb"),
		}
		return openers[self.kind]()  # type: ignore[return-value]

	@property
	def _inner_name(self) -> str:
		name = self.path.name
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
				compressed_size=self.path.stat().st_size,
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
	"""

	def __init__(self, path: Path, kind: str, read_cap: int = DEFAULT_READ_CAP) -> None:
		super().__init__(path, kind, read_cap)
		try:
			import py7zr
		except ImportError as error:  # pragma: no cover - dépend de l'environnement
			raise UnsupportedArchive(
				"Archive 7z détectée : installe la dépendance optionnelle avec "
				'pip install "zipguard[7z]".'
			) from error
		self._py7zr = py7zr
		self._archive = py7zr.SevenZipFile(self.path, mode="r")

	def _read_entries(self) -> list[Entry]:
		entries: list[Entry] = []
		for info in self._archive.list():
			entries.append(
				Entry(
					name=info.filename,
					size=int(getattr(info, "uncompressed", 0) or 0),
					compressed_size=int(getattr(info, "compressed", 0) or 0),
					is_dir=bool(getattr(info, "is_directory", False)),
				)
			)
		return entries

	def open(self, entry: Entry) -> IO[bytes]:
		if entry.size > self.read_cap:
			raise ReadCapExceeded(self.read_cap, entry.size)
		self._archive.reset()
		extracted = self._archive.read([entry.name]) or {}
		stream = extracted.get(entry.name)
		if stream is None:
			raise KeyError(f"Entrée introuvable dans l'archive : {entry.name}")
		return stream

	def close(self) -> None:
		self._archive.close()


def open_archive(path: Path, read_cap: int = DEFAULT_READ_CAP) -> Archive:
	"""
	Description: Ouvre n'importe quelle archive prise en charge derrière une interface unique.
	Usage: with open_archive(Path("a.tar.gz"), read_cap=1_000_000) as handle: handle.entries().
	Inputs: path (Path) archive, read_cap (int) plafond d'octets décompressés lus.
	Outputs: Archive adaptée au format détecté.

	Lève UnsupportedArchive quand la signature n'est reconnue par aucun adaptateur.
	"""

	path = Path(path)
	kind = detect_kind(path)
	if kind is None:
		raise UnsupportedArchive(f"Format non reconnu ou fichier illisible : {path}")

	if kind == "zip":
		return ZipArchive(path, kind, read_cap)
	if kind in TAR_KINDS:
		return TarArchive(path, kind, read_cap)
	if kind in STREAM_KINDS:
		return StreamArchive(path, kind, read_cap)
	if kind == "7z":
		return SevenZipArchive(path, kind, read_cap)

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
