from __future__ import annotations

import hashlib
import json

from .limits import REASON_CODES, Verdict
from .report import printable

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
	"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/Picsou06/zipguard"
HELP_URI = "https://github.com/Picsou06/zipguard/blob/main/docs/02-prevention.md"

# Le niveau SARIF décide de la couleur dans l'onglet Sécurité, la gravité de sécurité de
# l'étiquette (critique, haute, moyenne, basse). Un fichier qui n'est pas une archive n'est
# qu'une note ; une archive qu'on n'a pas su lire est un avertissement ; tout le reste est un
# refus franc.
_LEVELS = {"unsupported": "note", "unreadable": "warning"}
_SEVERITY = {
	"ratio": "8.0",
	"total_size": "8.0",
	"entry_size": "7.0",
	"too_many_entries": "6.0",
	"read_cap": "8.0",
	"nested": "8.0",
	"nested_cut": "7.0",
	"depth": "6.0",
	"nested_budget": "6.0",
	"encrypted": "5.0",
	"download_cap": "5.0",
	"download_timeout": "5.0",
	"memory": "7.0",
	"unreadable": "3.0",
	"unsupported": "1.0",
}


def rule_id(code: str) -> str:
	"""
	Description: Identifiant de règle SARIF d'un code de refus.
	Usage: rule_id("ratio") -> "zipguard/ratio".
	Inputs: code (str) clé de REASON_CODES.
	Outputs: str identifiant stable.
	"""

	return f"zipguard/{code}"


def _rules() -> list[dict]:
	"""
	Description: Décrit chaque garde fou comme une règle SARIF.
	Usage: interne à render_sarif.
	Inputs: aucun.
	Outputs: list[dict] des règles, une par code de refus.
	"""

	return [
		{
			"id": rule_id(code),
			"name": "".join(part.capitalize() for part in code.split("_")),
			"shortDescription": {"text": label},
			"fullDescription": {"text": f"ZipGuard refuse l'archive : {label.lower()}."},
			"helpUri": HELP_URI,
			"help": {"text": f"{label}. Détails et justification : {HELP_URI}"},
			"defaultConfiguration": {"level": _LEVELS.get(code, "error")},
			"properties": {
				"tags": ["security", "decompression-bomb"],
				"security-severity": _SEVERITY.get(code, "5.0"),
			},
		}
		for code, label in REASON_CODES.items()
	]


def _fingerprint(uri: str, code: str) -> str:
	return hashlib.sha256(f"{uri}\0{code}".encode()).hexdigest()


def _results(uri: str, verdict: Verdict) -> list[dict]:
	"""
	Description: Transforme les raisons d'un verdict en résultats SARIF.
	Usage: interne à render_sarif.
	Inputs: uri (str) chemin de l'archive, verdict (Verdict).
	Outputs: list[dict] un résultat par raison de refus.

	Une archive peut être refusée pour plusieurs raisons à la fois : chacune devient un
	résultat distinct, rattaché à sa propre règle, pour que l'onglet Sécurité les compte et
	les ferme séparément.
	"""

	results = []
	for code, message in zip(verdict.codes, verdict.reasons, strict=False):
		results.append(
			{
				"ruleId": rule_id(code),
				"level": _LEVELS.get(code, "error"),
				"message": {"text": printable(message)},
				"locations": [
					{
						"physicalLocation": {
							"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
							"region": {"startLine": 1},
						}
					}
				],
				"partialFingerprints": {"zipguardFinding/v1": _fingerprint(uri, code)},
				"properties": {"stats": {k: v for k, v in verdict.stats.items() if k != "name"}},
			}
		)
	return results


def render_sarif(results: list[tuple[str, Verdict]], *, indent: int | None = 2) -> str:
	"""
	Description: Construit un rapport SARIF 2.1.0 à partir de verdicts.
	Usage: print(render_sarif([("lib/a.zip", verdict)])).
	Inputs: results (list[tuple[str, Verdict]]) couples chemin relatif et verdict, indent (int | None).
	Outputs: str JSON SARIF, prête pour github/codeql-action/upload-sarif.

	Les chemins doivent être relatifs à la racine du dépôt, en séparateurs /, pour que
	GitHub rattache chaque refus au bon fichier dans l'onglet Sécurité.
	"""

	from . import __version__

	document = {
		"$schema": SARIF_SCHEMA,
		"version": SARIF_VERSION,
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "ZipGuard",
						"version": __version__,
						"semanticVersion": __version__,
						"informationUri": INFORMATION_URI,
						"rules": _rules(),
					}
				},
				"invocations": [{"executionSuccessful": True}],
				"results": [item for uri, verdict in results for item in _results(uri, verdict)],
			}
		],
	}
	return json.dumps(document, ensure_ascii=False, indent=indent)
