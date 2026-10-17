from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

SAFE_CAP_BYTES = 100_000_000
FORMATS = ("zip", "tar.gz")


def _write_zip(destination: Path, name: str, payload: bytes) -> None:
	"""
	Description: Écrit la démonstration dans une archive ZIP à une seule entrée.
	Usage: interne à build_demo_archive.
	Inputs: destination (Path) fichier à écrire, name (str) nom de l'entrée, payload (bytes) contenu.
	Outputs: None.
	"""

	with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		archive.writestr(name, payload)


def _write_targz(destination: Path, name: str, payload: bytes) -> None:
	"""
	Description: Écrit la démonstration dans une archive tar.gz à une seule entrée.
	Usage: interne à build_demo_archive.
	Inputs: destination (Path) fichier à écrire, name (str) nom de l'entrée, payload (bytes) contenu.
	Outputs: None.
	"""

	with tarfile.open(destination, "w:gz") as archive:
		info = tarfile.TarInfo(name)
		info.size = len(payload)
		archive.addfile(info, io.BytesIO(payload))


_WRITERS = {"zip": _write_zip, "tar.gz": _write_targz}


def build_demo_archive(
	destination: Path,
	text: str = "zizi",
	megabytes: int = 10,
	archive_format: str = "zip",
) -> dict:
	"""
	Description: Fabrique une archive de démonstration bornée pour illustrer le ratio de compression sans danger.
	Usage: build_demo_archive(Path("demo.zip"), text="motif", megabytes=10, archive_format="tar.gz").
	Inputs: destination (Path) fichier à écrire, text (str) motif répété, megabytes (int) taille non compressée voulue, archive_format (str) zip ou tar.gz.
	Outputs: dict contenant le format, les tailles et le ratio obtenus.

	La taille non compressée est plafonnée à SAFE_CAP_BYTES. Il n'y a ni récursion, ni
	imbrication, ni expansion cachée : l'archive se décompresse exactement à la taille
	annoncée, dans les deux formats.
	"""

	if archive_format not in _WRITERS:
		raise ValueError(
			f"Format de démonstration inconnu : {archive_format}. Formats acceptés : {', '.join(FORMATS)}."
		)

	target_bytes = megabytes * 1_000_000
	if target_bytes <= 0:
		raise ValueError("La taille doit être strictement positive.")
	if target_bytes > SAFE_CAP_BYTES:
		raise ValueError(
			f"Démonstration plafonnée à {SAFE_CAP_BYTES // 1_000_000} Mo pour rester inoffensive."
		)

	unit = (text + "\n").encode("utf-8")
	repeats = max(1, target_bytes // len(unit))
	payload = unit * repeats

	destination.parent.mkdir(parents=True, exist_ok=True)
	_WRITERS[archive_format](destination, f"{text}.txt", payload)

	compressed = destination.stat().st_size
	uncompressed = len(payload)
	return {
		"path": str(destination),
		"format": archive_format,
		"uncompressed": uncompressed,
		"compressed": compressed,
		"ratio": round(uncompressed / max(1, compressed), 2),
	}
