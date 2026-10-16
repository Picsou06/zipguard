from __future__ import annotations

from .limits import Verdict, human_bytes


def render(path: str, verdict: Verdict) -> str:
	"""
	Description: Construit un rapport texte lisible à partir d'un verdict d'inspection.
	Usage: print(render("a.zip", verdict)).
	Inputs: path (str) nom de l'archive, verdict (Verdict) résultat d'inspection.
	Outputs: str prête à être affichée dans un terminal.
	"""

	status = "SÛRE" if verdict.safe else "DANGEREUSE"
	mark = "✅" if verdict.safe else "⛔"
	lines = [
		"",
		f"  {mark}  ZipGuard — rapport d'inspection",
		f"      Archive : {path}",
		f"      Verdict : {status}",
		"",
	]

	if verdict.stats:
		s = verdict.stats
		lines += [
			"      Statistiques",
			f"        entrées              : {s['entries']}",
			f"        taille compressée    : {human_bytes(s['total_compressed'])}",
			f"        taille décompressée  : {human_bytes(s['total_uncompressed'])}",
			f"        ratio                : {s['ratio']}x",
			f"        plus grosse entrée   : {human_bytes(s['biggest_entry'])}",
			f"        archives imbriquées  : {s['nested_archives']}",
			"",
		]

	if verdict.reasons:
		lines.append("      Raisons du refus")
		for reason in verdict.reasons:
			lines.append(f"        • {reason}")
		lines.append("")

	return "\n".join(lines)
