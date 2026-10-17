from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest


def write_zip(path: Path, files: dict[str, bytes]) -> Path:
	"""
	Description: Fabrique une archive ZIP de test à partir d'un dictionnaire de contenus.
	Usage: write_zip(tmp_path / "a.zip", {"a.txt": b"bonjour"}).
	Inputs: path (Path) destination, files (dict[str, bytes]) nom d'entrée vers contenu.
	Outputs: Path de l'archive écrite.
	"""

	with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		for name, data in files.items():
			archive.writestr(name, data)
	return path


def write_tar(path: Path, files: dict[str, bytes], mode: str = "w:gz") -> Path:
	"""
	Description: Fabrique une archive tar (éventuellement compressée) pour les tests.
	Usage: write_tar(tmp_path / "a.tar.gz", {"a.txt": b"bonjour"}).
	Inputs: path (Path) destination, files (dict[str, bytes]) contenus, mode (str) mode tarfile.
	Outputs: Path de l'archive écrite.
	"""

	with tarfile.open(path, mode) as archive:
		for name, data in files.items():
			info = tarfile.TarInfo(name)
			info.size = len(data)
			archive.addfile(info, io.BytesIO(data))
	return path


@pytest.fixture
def zip_factory(tmp_path: Path):
	"""
	Description: Fixture fabriquant des archives ZIP numérotées dans le dossier temporaire.
	Usage: path = zip_factory({"a.txt": b"x"}).
	Inputs: aucun au moment de la fixture ; appel avec un dict de contenus.
	Outputs: callable renvoyant le Path de l'archive créée.
	"""

	counter = {"n": 0}

	def make(files: dict[str, bytes], name: str | None = None) -> Path:
		counter["n"] += 1
		target = tmp_path / (name or f"archive{counter['n']}.zip")
		return write_zip(target, files)

	return make
