from __future__ import annotations

import zipfile
from pathlib import Path

SAFE_CAP_BYTES = 100_000_000


def build_demo_archive(destination: Path, text: str = "zizi", megabytes: int = 10) -> dict:
	"""
	Description: Fabrique une archive de démonstration bornée pour illustrer le ratio de compression sans danger.
	Usage: build_demo_archive(Path("demo.zip"), text="zizi", megabytes=10).
	Inputs: destination (Path) fichier zip à écrire, text (str) motif répété, megabytes (int) taille non compressée voulue.
	Outputs: dict contenant les tailles et le ratio obtenus.

	La taille non compressée est plafonnée à SAFE_CAP_BYTES. Il n'y a ni récursion, ni
	imbrication, ni expansion cachée : l'archive se décompresse exactement à la taille annoncée.
	"""

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
	with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		archive.writestr(f"{text}.txt", payload)

	compressed = destination.stat().st_size
	uncompressed = len(payload)
	return {
		"path": str(destination),
		"uncompressed": uncompressed,
		"compressed": compressed,
		"ratio": round(uncompressed / max(1, compressed), 2),
	}
