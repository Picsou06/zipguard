from __future__ import annotations

import os
import struct
import zipfile
from pathlib import Path

from zipguard import Limits, Scanner

EOCD_SIGNATURE = b"PK\x05\x06"
CD_SIGNATURE = b"PK\x01\x02"


def _read_eocd(blob: bytes) -> tuple[int, int, int]:
	"""
	Description: Lit la fin du répertoire central d'une archive ZIP.
	Usage: count, size, offset = _read_eocd(blob).
	Inputs: blob (bytes) archive complète.
	Outputs: tuple du nombre d'entrées, de la taille et de l'offset du répertoire central.
	"""

	start = blob.rfind(EOCD_SIGNATURE)
	assert start != -1, "Archive sans fin de répertoire central"
	count = struct.unpack("<H", blob[start + 10 : start + 12])[0]
	size = struct.unpack("<I", blob[start + 12 : start + 16])[0]
	offset = struct.unpack("<I", blob[start + 16 : start + 20])[0]
	return count, size, offset


def build_overlapping_zip(path: Path, copies: int, payload: bytes) -> Path:
	"""
	Description: Fabrique une archive dont les entrées pointent toutes vers les mêmes données compressées.
	Usage: build_overlapping_zip(tmp_path / "overlap.zip", 20, payload).
	Inputs: path (Path) destination, copies (int) nombre d'entrées déclarées, payload (bytes) contenu réel.
	Outputs: Path de l'archive écrite.

	C'est la troisième famille décrite dans le cours : un seul bloc compressé, référencé
	plusieurs fois par le répertoire central. L'archive coûte un bloc sur le disque mais en
	promet autant que de références. Rien d'offensif ici, tout est borné par payload.
	"""

	seed = path.with_suffix(".seed.zip")
	with zipfile.ZipFile(seed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		archive.writestr("fichier00.txt", payload)

	blob = seed.read_bytes()
	_, cd_size, cd_offset = _read_eocd(blob)
	local_part = blob[:cd_offset]
	central = blob[cd_offset : cd_offset + cd_size]
	assert central.startswith(CD_SIGNATURE)

	name_length = struct.unpack("<H", central[28:30])[0]
	name_start = 46
	directory = bytearray()
	for index in range(copies):
		record = bytearray(central)
		name = f"fichier{index:02d}.txt".encode()
		assert len(name) == name_length, "Les noms doivent garder la même longueur"
		record[name_start : name_start + name_length] = name
		directory += record

	eocd = bytearray(EOCD_SIGNATURE)
	eocd += struct.pack("<HH", 0, 0)
	eocd += struct.pack("<HH", copies, copies)
	eocd += struct.pack("<II", len(directory), len(local_part))
	eocd += struct.pack("<H", 0)

	path.write_bytes(local_part + bytes(directory) + bytes(eocd))
	seed.unlink()
	return path


def _payload() -> bytes:
	"""
	Description: Produit un contenu qui se compresse environ cinquante fois, pas davantage.
	Usage: payload = _payload().
	Inputs: aucun.
	Outputs: bytes d'un mégaoctet.

	Un ratio modéré est indispensable à la démonstration : chaque entrée prise isolément
	doit passer sous le seuil, pour que seul le recouvrement trahisse l'archive.
	"""

	return os.urandom(20_000) * 50


def test_the_archive_really_declares_many_entries(tmp_path: Path) -> None:
	archive = build_overlapping_zip(tmp_path / "overlap.zip", 20, _payload())
	with zipfile.ZipFile(archive) as handle:
		assert len(handle.infolist()) == 20


def test_each_entry_taken_alone_looks_reasonable(tmp_path: Path) -> None:
	archive = build_overlapping_zip(tmp_path / "overlap.zip", 20, _payload())
	with zipfile.ZipFile(archive) as handle:
		info = handle.infolist()[0]
		assert info.file_size / info.compress_size < 100


def test_the_archive_is_far_smaller_than_the_sum_of_its_entries(tmp_path: Path) -> None:
	archive = build_overlapping_zip(tmp_path / "overlap.zip", 20, _payload())
	with zipfile.ZipFile(archive) as handle:
		declared = sum(info.compress_size for info in handle.infolist())
	assert archive.stat().st_size < declared / 10


def test_overlapping_entries_are_refused(tmp_path: Path) -> None:
	archive = build_overlapping_zip(tmp_path / "overlap.zip", 20, _payload())
	verdict = Scanner(Limits(max_ratio=100.0)).inspect(archive)
	assert verdict.safe is False
	assert any("Ratio" in reason for reason in verdict.reasons)


def test_the_ratio_is_computed_against_the_real_file_size(tmp_path: Path) -> None:
	archive = build_overlapping_zip(tmp_path / "overlap.zip", 20, _payload())
	verdict = Scanner(Limits(max_ratio=100_000.0)).inspect(archive)
	assert verdict.stats["total_compressed"] <= archive.stat().st_size


def test_a_normal_archive_keeps_its_usual_ratio(tmp_path: Path) -> None:
	archive = tmp_path / "normale.zip"
	with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
		handle.writestr("a.txt", b"bonjour le monde" * 10)
	verdict = Scanner().inspect(archive)
	assert verdict.safe is True


def test_scanning_an_overlapping_archive_leaks_no_warning(tmp_path: Path, recwarn) -> None:
	archive = build_overlapping_zip(tmp_path / "overlap.zip", 20, _payload())
	Scanner(Limits(max_ratio=100.0)).inspect(archive)
	leaked = [warning for warning in recwarn if "Overlapped" in str(warning.message)]
	assert leaked == [], "Le rapport ne doit pas être pollué par un avertissement de zipfile"
