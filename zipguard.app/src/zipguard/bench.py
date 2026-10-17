from __future__ import annotations

import gzip
import io
import json
import tarfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .limits import Limits, human_bytes
from .report import ASCII_GLYPHS, UNICODE_GLYPHS, colour_enabled, glyphs_supported, paint
from .scanner import Scanner

SCHEMA_VERSION = 1
CORPUS_CAP_BYTES = 1_000_000
PAYLOAD_BYTES = 4_000_000


@dataclass(frozen=True)
class Case:
	"""
	Description: Un cas du banc d'essai : une archive, les seuils à appliquer, et le verdict attendu.
	Usage: for case in build_corpus(directory): ...
	Inputs: name (str), path (Path), limits (Limits), expectation (bool) verdict attendu, guard (str) garde fou visé.
	Outputs: structure immuable décrivant un cas de mesure.
	"""

	name: str
	path: Path
	limits: Limits
	expectation: bool
	guard: str


@dataclass(frozen=True)
class Result:
	"""
	Description: Mesure obtenue pour un cas : verdict rendu, temps écoulé, volume traité.
	Usage: for result in run_bench(cases): print(result.elapsed_ms).
	Inputs: name (str), guard (str), kind (str), safe (bool), expected (bool), elapsed_ms (float), archive_bytes (int), read_bytes (int), reason (str).
	Outputs: structure immuable sérialisable.
	"""

	name: str
	guard: str
	kind: str
	safe: bool
	expected: bool
	elapsed_ms: float
	archive_bytes: int
	read_bytes: int
	reason: str

	@property
	def ok(self) -> bool:
		"""
		Description: Dit si le verdict rendu correspond à celui attendu pour ce cas.
		Usage: result.ok.
		Inputs: aucun.
		Outputs: bool vrai quand le garde fou a réagi comme prévu.
		"""

		return self.safe == self.expected

	def as_dict(self) -> dict:
		"""
		Description: Convertit la mesure en structure JSON.
		Usage: json.dumps(result.as_dict()).
		Inputs: aucun.
		Outputs: dict sérialisable.
		"""

		return {
			"name": self.name,
			"guard": self.guard,
			"kind": self.kind,
			"safe": self.safe,
			"expected": self.expected,
			"ok": self.ok,
			"elapsed_ms": round(self.elapsed_ms, 3),
			"archive_bytes": self.archive_bytes,
			"read_bytes": self.read_bytes,
			"reason": self.reason,
		}


def _zip(path: Path, files: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> Path:
	"""
	Description: Écrit une archive ZIP du corpus.
	Usage: _zip(directory / "a.zip", {"a.txt": b"x"}).
	Inputs: path (Path) destination, files (dict[str, bytes]) contenus, compression (int) méthode.
	Outputs: Path de l'archive.
	"""

	with zipfile.ZipFile(path, "w", compression=compression) as archive:
		for name, data in files.items():
			archive.writestr(name, data)
	return path


def _targz(path: Path, files: dict[str, bytes]) -> Path:
	"""
	Description: Écrit une archive tar.gz du corpus.
	Usage: _targz(directory / "a.tar.gz", {"a.txt": b"x"}).
	Inputs: path (Path) destination, files (dict[str, bytes]) contenus.
	Outputs: Path de l'archive.
	"""

	with tarfile.open(path, "w:gz") as archive:
		for name, data in files.items():
			info = tarfile.TarInfo(name)
			info.size = len(data)
			archive.addfile(info, io.BytesIO(data))
	return path


def build_corpus(directory: Path) -> list[Case]:
	"""
	Description: Fabrique un corpus synthétique couvrant chaque garde fou, sans rien d'offensif.
	Usage: cases = build_corpus(Path("corpus")).
	Inputs: directory (Path) dossier où écrire les archives.
	Outputs: list[Case] prête à mesurer.

	Chaque cas porte ses propres seuils plutôt que l'inverse : c'est ce qui permet de viser
	un garde fou à la fois avec des archives qui restent minuscules sur le disque. Aucune ne
	dépasse CORPUS_CAP_BYTES compressée, aucune ne s'imbrique au delà d'un niveau, et toutes
	se décompressent à une taille connue d'avance. Le corpus mesure une défense, il ne
	fournit pas une arme.
	"""

	directory = Path(directory)
	directory.mkdir(parents=True, exist_ok=True)
	payload = b"A" * PAYLOAD_BYTES

	nested_inner = _zip(directory / "_interne.zip", {"gros.txt": payload})
	nested_outer = directory / "imbriquee.zip"
	with zipfile.ZipFile(nested_outer, "w", compression=zipfile.ZIP_STORED) as archive:
		archive.write(nested_inner, "interne.zip")

	plain = directory / "pas-une-archive.txt"
	plain.write_text("Ceci n'est pas une archive, et ZipGuard doit le dire sans planter.")

	stream = directory / "flux.txt.gz"
	with gzip.open(stream, "wb") as handle:
		handle.write(payload)

	return [
		Case(
			name="benigne.zip",
			path=_zip(directory / "benigne.zip", {f"note{i}.txt": b"bonjour" for i in range(5)}),
			limits=Limits(),
			expectation=True,
			guard="aucun",
		),
		Case(
			name="ratio.zip",
			path=_zip(directory / "ratio.zip", {"gros.txt": payload}),
			limits=Limits(max_ratio=50.0),
			expectation=False,
			guard="ratio",
		),
		Case(
			name="entrees.zip",
			path=_zip(directory / "entrees.zip", {f"f{i}.txt": b"x" for i in range(500)}),
			limits=Limits(max_entries=100),
			expectation=False,
			guard="max_entries",
		),
		Case(
			name="entree-unique.zip",
			path=_zip(directory / "entree-unique.zip", {"gros.txt": payload}),
			limits=Limits(max_entry_bytes=1_000_000, max_ratio=100_000.0),
			expectation=False,
			guard="max_entry_bytes",
		),
		Case(
			name="total.zip",
			path=_zip(directory / "total.zip", {"gros.txt": payload}),
			limits=Limits(
				max_total_bytes=1_000_000,
				max_entry_bytes=100_000_000,
				max_ratio=100_000.0,
			),
			expectation=False,
			guard="max_total_bytes",
		),
		Case(
			name="imbriquee.zip",
			path=nested_outer,
			limits=Limits(max_ratio=50.0, max_depth=2),
			expectation=False,
			guard="imbrication",
		),
		Case(
			name="imbriquee-profondeur.zip",
			path=nested_outer,
			limits=Limits(max_depth=0),
			expectation=False,
			guard="max_depth",
		),
		Case(
			name="mesure.tar.gz",
			path=_targz(directory / "mesure.tar.gz", {"gros.txt": payload}),
			limits=Limits(max_ratio=50.0),
			expectation=False,
			guard="ratio_mesure",
		),
		Case(
			name="lecture-coupee.tar.gz",
			path=_targz(directory / "lecture-coupee.tar.gz", {"gros.txt": payload}),
			limits=Limits(max_total_bytes=500_000),
			expectation=False,
			guard="plafond_de_lecture",
		),
		Case(
			name="flux.txt.gz",
			path=stream,
			limits=Limits(max_ratio=50.0),
			expectation=False,
			guard="flux_compresse",
		),
		Case(
			name="pas-une-archive.txt",
			path=plain,
			limits=Limits(),
			expectation=False,
			guard="format",
		),
	]


def run_bench(cases: list[Case], repeat: int = 3) -> list[Result]:
	"""
	Description: Mesure le temps que met chaque garde fou à trancher, et vérifie qu'il tranche bien.
	Usage: results = run_bench(build_corpus(directory)).
	Inputs: cases (list[Case]) corpus, repeat (int) nombre de passes par cas.
	Outputs: list[Result] une mesure par cas.

	On garde la passe la plus rapide : les ralentissements viennent du système, jamais du
	code mesuré, donc la médiane ou la moyenne ne feraient qu'y mêler du bruit.
	"""

	results: list[Result] = []
	for case in cases:
		scanner = Scanner(case.limits)
		best = float("inf")
		verdict = None
		for _ in range(max(1, repeat)):
			started = time.perf_counter()
			verdict = scanner.inspect(case.path)
			best = min(best, (time.perf_counter() - started) * 1000)

		assert verdict is not None
		results.append(
			Result(
				name=case.name,
				guard=case.guard,
				kind=str(verdict.stats.get("kind") or "inconnu"),
				safe=verdict.safe,
				expected=case.expectation,
				elapsed_ms=best,
				archive_bytes=case.path.stat().st_size,
				read_bytes=int(verdict.stats.get("total_uncompressed", 0)),
				reason=verdict.reasons[0] if verdict.reasons else "",
			)
		)
	return results


def render_bench(
	results: list[Result],
	*,
	color: bool | None = None,
	unicode: bool | None = None,
) -> str:
	"""
	Description: Met les mesures en table lisible dans un terminal.
	Usage: print(render_bench(results)).
	Inputs: results (list[Result]) mesures, color (bool | None) couleurs, unicode (bool | None) pictogrammes.
	Outputs: str de la table complète.
	"""

	enabled = colour_enabled(color)
	glyphs = UNICODE_GLYPHS if (glyphs_supported() if unicode is None else unicode) else ASCII_GLYPHS

	name_width = max(24, max((len(result.name) for result in results), default=0) + 2)
	widths = (name_width, 20, 10, 12, 11, 12)
	header = (
		"cas".ljust(widths[0])
		+ "garde fou".ljust(widths[1])
		+ "format".ljust(widths[2])
		+ "verdict".ljust(widths[3])
		+ "temps".rjust(widths[4])
		+ "lu".rjust(widths[5])
	)
	rule = glyphs["rule"] * (sum(widths) + 2)

	title = paint("ZipGuard", "bold", "cyan", enabled=enabled)
	subtitle = paint("{} banc d'essai".format(glyphs["dot"]), "dim", enabled=enabled)

	lines = [
		"",
		f"  {title} {subtitle}",
		f"  {paint(rule, 'dim', enabled=enabled)}",
		f"  {paint(header, 'dim', enabled=enabled)}",
		f"  {paint(rule, 'dim', enabled=enabled)}",
	]

	for result in results:
		verdict_word = "SÛRE" if result.safe else "REFUSÉE"
		colour = "green" if result.safe else "red"
		mark = glyphs["safe"] if result.ok else glyphs["danger"]
		lines.append(
			"  "
			+ result.name.ljust(widths[0])
			+ result.guard.ljust(widths[1])
			+ result.kind.ljust(widths[2])
			+ paint(verdict_word.ljust(widths[3]), colour, enabled=enabled)
			+ f"{result.elapsed_ms:.2f} ms".rjust(widths[4])
			+ human_bytes(result.read_bytes).rjust(widths[5])
			+ ("" if result.ok else f"  {mark} inattendu")
		)

	unexpected = [result for result in results if not result.ok]
	total = sum(result.elapsed_ms for result in results)
	lines += [
		f"  {paint(rule, 'dim', enabled=enabled)}",
		f"  {len(results)} cas, {total:.1f} ms au total, {len(unexpected)} verdict(s) inattendu(s)",
		"",
	]
	return "\n".join(lines)


def bench_json(results: list[Result], indent: int | None = 2) -> str:
	"""
	Description: Sérialise les mesures du banc pour un suivi dans le temps.
	Usage: print(bench_json(results, indent=None)).
	Inputs: results (list[Result]) mesures, indent (int | None) mise en forme.
	Outputs: str JSON.
	"""

	from . import __version__

	payload = {
		"schema_version": SCHEMA_VERSION,
		"tool": "zipguard",
		"version": __version__,
		"summary": {
			"cases": len(results),
			"unexpected": sum(1 for result in results if not result.ok),
			"total_ms": round(sum(result.elapsed_ms for result in results), 3),
		},
		"cases": [result.as_dict() for result in results],
	}
	separators = (",", ":") if indent is None else None
	return json.dumps(payload, ensure_ascii=False, indent=indent, separators=separators)
