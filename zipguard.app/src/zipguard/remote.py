from __future__ import annotations

import io
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import PurePosixPath
from typing import IO

from .sources import Source

DEFAULT_TIMEOUT = 30.0
_CHUNK = 65536

# Un saut vers l'avant plus court que ceci est lu et jeté sur la réponse déjà ouverte plutôt
# que de payer une nouvelle requête. Dans un zip, passer d'une entrée à la suivante est
# presque toujours un petit saut : mesuré sur une roue numpy de 15 Mio et mille fichiers,
# on passe d'un millier de requêtes (24 s) à une vingtaine (moins d'une seconde), pour
# 3,5 Mio téléchargés au lieu de 1,5.
_SKIP_AHEAD = 64 * 1024
_CONTENT_RANGE = re.compile(r"^bytes (\d+)-(\d+)/(\d+|\*)$")


class RemoteError(OSError):
	"""
	Description: Signale qu'une archive distante ne peut pas être lue comme ZipGuard l'exige.
	Usage: levée par RemoteSource quand le serveur répond mal ou cache la taille du fichier.
	Inputs: message (str) cause.
	Outputs: exception dérivant d'OSError, traitée comme une erreur de lecture.
	"""


class DownloadCapExceeded(OSError):
	"""
	Description: Signale que l'inspection a téléchargé plus que le plafond autorisé.
	Usage: levée pendant une lecture ; le scanner la traduit en refus « download_cap ».
	Inputs: cap (int) plafond, downloaded (int) octets lus.
	Outputs: exception dérivant d'OSError, pour couper toute lecture en cours.
	"""

	def __init__(self, cap: int, downloaded: int) -> None:
		super().__init__(f"Plafond de téléchargement de {cap} o atteint ({downloaded} o lus).")
		self.cap = cap
		self.downloaded = downloaded


def is_url(target: str) -> bool:
	"""
	Description: Dit si un argument désigne une archive distante.
	Usage: is_url("https://exemple.org/a.zip").
	Inputs: target (str) argument tel que tapé.
	Outputs: bool vrai pour http et https seulement.
	"""

	return target.lower().startswith(("http://", "https://"))


class RemoteSource(Source):
	"""
	Description: Archive servie en HTTP, lue par plages sans jamais être posée sur le disque.
	Usage: RemoteSource("https://exemple.org/a.zip", max_download_bytes=50_000_000).
	Inputs: url (str) adresse http ou https, max_download_bytes (int) plafond de téléchargement, timeout (float) délai de chaque requête.
	Outputs: Source distante ; downloaded compte les octets réellement lus.

	Le gain est maximal pour un zip : son manifeste est en fin de fichier, donc une requête
	sur la fin, puis une par entrée pour en lire la signature, suffisent à juger une archive
	de plusieurs gigaoctets en ne téléchargeant que quelques kilo-octets. Un tar ou un flux
	compressé doit être lu dans l'ordre, mais il l'est derrière le même plafond de lecture
	que sur disque, et derrière un plafond de téléchargement en plus.

	Si le serveur ne permet pas la lecture par plages, seuls les formats lisibles d'un trait
	restent inspectables ; zip et 7z sont alors refusés avec une raison claire.
	"""

	on_disk = False

	def __init__(
		self,
		url: str,
		*,
		max_download_bytes: int = 200_000_000,
		timeout: float = DEFAULT_TIMEOUT,
	) -> None:
		parts = urllib.parse.urlsplit(url)
		if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
			raise ValueError(f"Adresse non prise en charge : {url} (http ou https attendu).")

		self.url = url
		self.name = PurePosixPath(urllib.parse.unquote(parts.path)).name or parts.netloc
		self.max_download_bytes = max_download_bytes
		self.timeout = timeout
		self.downloaded = 0
		self.requests = 0
		self.cap_exceeded = False
		self._size, self.seekable = self._probe()

	def size(self) -> int:
		return self._size

	def open(self) -> IO[bytes]:
		return _HttpReader(self)

	def _request(self, start: int, *, ranged: bool):
		"""
		Description: Ouvre une réponse HTTP à partir d'un décalage donné.
		Usage: interne.
		Inputs: start (int) premier octet voulu, ranged (bool) demander une plage.
		Outputs: réponse urllib, à refermer par l'appelant.
		"""

		from . import __version__

		headers = {"User-Agent": f"zipguard/{__version__}", "Accept-Encoding": "identity"}
		if ranged:
			headers["Range"] = f"bytes={start}-"
		request = urllib.request.Request(self.url, headers=headers)
		self.requests += 1
		try:
			return urllib.request.urlopen(request, timeout=self.timeout)
		except urllib.error.HTTPError as error:
			raise RemoteError(f"Le serveur a répondu {error.code} pour {self.url}.") from error

	def _probe(self) -> tuple[int, bool]:
		"""
		Description: Interroge le serveur sur la taille du fichier et la lecture par plages.
		Usage: interne au constructeur.
		Inputs: aucun.
		Outputs: tuple (taille en octets, lecture par plages possible).

		La taille est indispensable : c'est le dénominateur du ratio. Un serveur qui ne
		l'annonce pas est refusé plutôt que deviné.
		"""

		# Une plage ouverte depuis l'octet 0 sert de sonde : un serveur qui sait servir des
		# plages répond 206 avec la taille totale, un autre répond 200 avec le fichier entier,
		# dont on ne lit rien.
		response = self._request(0, ranged=True)
		try:
			self._check_encoding(response)
			if response.status == 206:
				match = _CONTENT_RANGE.match(response.headers.get("Content-Range", ""))
				if match is None or match.group(3) == "*":
					raise RemoteError("Réponse partielle sans taille totale (Content-Range).")
				return int(match.group(3)), True
			length = response.headers.get("Content-Length")
			if length is None or not length.isdigit():
				raise RemoteError("Le serveur n'annonce pas la taille du fichier (Content-Length).")
			return int(length), False
		finally:
			response.close()

	@staticmethod
	def _check_encoding(response) -> None:
		encoding = (response.headers.get("Content-Encoding") or "identity").lower()
		if encoding != "identity":
			raise RemoteError(
				f"Le serveur recompresse le fichier ({encoding}) : les octets lus ne seraient "
				"pas ceux de l'archive."
			)

	def _consume(self, count: int) -> None:
		"""
		Description: Compte des octets téléchargés, et coupe au plafond.
		Usage: interne à _HttpReader.
		Inputs: count (int) octets venant d'être lus.
		Outputs: None, lève DownloadCapExceeded au dépassement.
		"""

		self.downloaded += count
		if self.downloaded > self.max_download_bytes:
			self.cap_exceeded = True
			raise DownloadCapExceeded(self.max_download_bytes, self.downloaded)


class _HttpReader(io.RawIOBase):
	"""
	Description: Flux binaire lisant une RemoteSource, déplaçable si le serveur sert des plages.
	Usage: rendu par RemoteSource.open().
	Inputs: source (RemoteSource).
	Outputs: objet fichier ; une lecture suivie réutilise la même réponse, un saut en ouvre une nouvelle.
	"""

	def __init__(self, source: RemoteSource) -> None:
		super().__init__()
		self._source = source
		self._position = 0
		self._response = None
		self._response_position = -1

	def readable(self) -> bool:
		return True

	def seekable(self) -> bool:
		return self._source.seekable

	def tell(self) -> int:
		return self._position

	def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
		if whence == io.SEEK_SET:
			target = offset
		elif whence == io.SEEK_CUR:
			target = self._position + offset
		elif whence == io.SEEK_END:
			target = self._source.size() + offset
		else:  # pragma: no cover - valeurs garanties par io
			raise ValueError(f"whence invalide : {whence}")
		if target < 0:
			raise OSError("Position négative.")
		if target != self._position and not self._source.seekable:
			raise io.UnsupportedOperation("Le serveur ne permet pas la lecture par plages.")
		self._position = target
		return target

	def _ensure_response(self) -> None:
		if self._response is not None and self._response_position == self._position:
			return
		ahead = self._position - self._response_position
		if self._response is not None and 0 < ahead <= _SKIP_AHEAD and self._skip_to_position():
			return
		self._drop_response()
		if self._position and not self._source.seekable:  # pragma: no cover - bloqué par seek
			raise io.UnsupportedOperation("Le serveur ne permet pas la lecture par plages.")

		response = self._source._request(self._position, ranged=self._source.seekable)
		RemoteSource._check_encoding(response)
		if self._source.seekable:
			match = _CONTENT_RANGE.match(response.headers.get("Content-Range", ""))
			if response.status != 206 or match is None or int(match.group(1)) != self._position:
				response.close()
				raise RemoteError("Le serveur n'a pas servi la plage demandée.")
		self._response = response
		self._response_position = self._position

	def _skip_to_position(self) -> bool:
		"""
		Description: Avance la réponse ouverte jusqu'à la position voulue en jetant l'écart.
		Usage: interne à _ensure_response.
		Inputs: aucun.
		Outputs: bool vrai si la réponse est maintenant alignée sur la position.
		"""

		gap = self._position - self._response_position
		while gap > 0:
			piece = self._response.read(min(_CHUNK, gap))
			if not piece:
				return False
			self._source._consume(len(piece))
			gap -= len(piece)
			self._response_position += len(piece)
		return True

	def _drop_response(self) -> None:
		if self._response is not None:
			self._response.close()
		self._response = None
		self._response_position = -1

	def read(self, size: int = -1) -> bytes:
		remaining = self._source.size() - self._position
		if remaining <= 0:
			return b""
		wanted = remaining if size is None or size < 0 else min(size, remaining)
		if wanted == 0:
			return b""

		self._ensure_response()
		pieces: list[bytes] = []
		got = 0
		while got < wanted:
			piece = self._response.read(min(_CHUNK, wanted - got))
			if not piece:
				break
			pieces.append(piece)
			got += len(piece)
			self._position += len(piece)
			self._response_position = self._position
			self._source._consume(len(piece))
		return b"".join(pieces)

	def readinto(self, buffer) -> int:  # pragma: no cover - utilisé par io.BufferedReader
		chunk = self.read(len(buffer))
		buffer[: len(chunk)] = chunk
		return len(chunk)

	def close(self) -> None:
		try:
			self._drop_response()
		finally:
			super().close()
