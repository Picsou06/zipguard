from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from conftest import write_zip
from zipguard import Scanner
from zipguard.scanner import ExtractionRefused


def write_flagged_zip(path: Path, files: dict[str, bytes], encrypted: set[str]) -> Path:
	"""
	Description: Fabrique un zip dont certaines entrées portent le drapeau « chiffrée ».
	Usage: write_flagged_zip(tmp_path / "a.zip", {"a.txt": b"x"}, {"a.txt"}).
	Inputs: path (Path) destination, files (dict) contenus, encrypted (set[str]) noms à marquer.
	Outputs: Path de l'archive écrite.

	zipfile ne sait pas chiffrer, et ZipGuard ne regarde que le drapeau : on écrit donc une
	archive normale, puis on lève le bit 0 dans l'en-tête local et dans le répertoire
	central, exactement là où un vrai outil de chiffrement le poserait.
	"""

	write_zip(path, files)
	blob = bytearray(path.read_bytes())
	with zipfile.ZipFile(path) as archive:
		infos = archive.infolist()
	for info in infos:
		if info.filename not in encrypted:
			continue
		local = info.header_offset
		flags = struct.unpack_from("<H", blob, local + 6)[0]
		struct.pack_into("<H", blob, local + 6, flags | 0x1)

	offset = blob.rfind(b"PK\x05\x06")
	central = struct.unpack_from("<I", blob, offset + 16)[0]
	position = central
	while blob[position : position + 4] == b"PK\x01\x02":
		name_length, extra_length, comment_length = struct.unpack_from("<HHH", blob, position + 28)
		name = bytes(blob[position + 46 : position + 46 + name_length]).decode()
		if name in encrypted:
			flags = struct.unpack_from("<H", blob, position + 8)[0]
			struct.pack_into("<H", blob, position + 8, flags | 0x1)
		position += 46 + name_length + extra_length + comment_length
	path.write_bytes(bytes(blob))
	return path


def test_an_encrypted_zip_gets_a_verdict_not_a_crash(tmp_path: Path) -> None:
	archive = write_flagged_zip(tmp_path / "chiffre.zip", {"a.txt": b"secret"}, {"a.txt"})
	verdict = Scanner().inspect(archive)
	assert verdict.safe is False
	assert "encrypted" in verdict.codes
	assert verdict.stats["encrypted_entries"] == 1


def test_a_single_encrypted_entry_is_enough_to_refuse(tmp_path: Path) -> None:
	archive = write_flagged_zip(
		tmp_path / "mixte.zip", {"clair.txt": b"bonjour", "cache.bin": b"x" * 100}, {"cache.bin"}
	)
	verdict = Scanner().inspect(archive)
	assert verdict.codes == ["encrypted"]
	assert verdict.stats["encrypted_entries"] == 1


def test_an_encrypted_entry_is_never_extracted_even_when_trusted(tmp_path: Path) -> None:
	from zipguard.trust import fingerprint

	archive = write_flagged_zip(tmp_path / "chiffre.zip", {"a.txt": b"secret"}, {"a.txt"})
	scanner = Scanner(trusted={fingerprint(archive)})
	with pytest.raises(ExtractionRefused, match="chiffrée"):
		scanner.safe_extract(archive, tmp_path / "out")
	assert not (tmp_path / "out").exists()


def test_a_plain_zip_has_no_encrypted_entries(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "clair.zip", {"a.txt": b"bonjour"})
	verdict = Scanner().inspect(archive)
	assert verdict.safe is True
	assert verdict.stats["encrypted_entries"] == 0
	assert verdict.codes == []


def test_every_refusal_carries_one_code_per_reason(tmp_path: Path) -> None:
	from zipguard import Limits

	archive = write_zip(tmp_path / "gros.zip", {"a.txt": b"A" * 300_000})
	verdict = Scanner(Limits(max_ratio=2.0, max_entry_bytes=1000)).inspect(archive)
	assert len(verdict.codes) == len(verdict.reasons)
	assert set(verdict.codes) == {"entry_size", "ratio"}


def test_codes_are_part_of_the_json(tmp_path: Path) -> None:
	archive = write_flagged_zip(tmp_path / "chiffre.zip", {"a.txt": b"secret"}, {"a.txt"})
	assert Scanner().inspect(archive).as_dict()["codes"] == ["encrypted"]


py7zr = pytest.importorskip("py7zr", reason="L'extra 7z n'est pas installé.")


def test_an_encrypted_seven_zip_is_refused(tmp_path: Path) -> None:
	archive = tmp_path / "chiffre.7z"
	with py7zr.SevenZipFile(archive, "w", password="motdepasse") as handle:
		handle.writestr(b"secret", "a.txt")
	verdict = Scanner().inspect(archive)
	assert verdict.safe is False
	assert "encrypted" in verdict.codes


def test_a_seven_zip_with_encrypted_headers_is_refused(tmp_path: Path) -> None:
	archive = tmp_path / "entetes.7z"
	with py7zr.SevenZipFile(archive, "w", password="motdepasse", header_encryption=True) as handle:
		handle.writestr(b"secret", "a.txt")
	verdict = Scanner().inspect(archive)
	assert verdict.safe is False
	assert verdict.codes == ["encrypted"]
	assert verdict.stats["encrypted"] is True
