from __future__ import annotations

import json
import os
import sys

from .limits import Limits, Verdict, human_bytes

SCHEMA_VERSION = 1
RULE_WIDTH = 68
GAUGE_WIDTH = 22

_ANSI = {
	"reset": "\x1b[0m",
	"bold": "\x1b[1m",
	"dim": "\x1b[2m",
	"red": "\x1b[31m",
	"green": "\x1b[32m",
	"yellow": "\x1b[33m",
	"cyan": "\x1b[36m",
}

UNICODE_GLYPHS = {
	"safe": "✅",
	"danger": "⛔",
	"full": "█",
	"empty": "░",
	"rule": "─",
	"branch": "└",
	"bullet": "•",
	"dot": "·",
}

ASCII_GLYPHS = {
	"safe": "[OK]",
	"danger": "[!!]",
	"full": "#",
	"empty": ".",
	"rule": "-",
	"branch": "`-",
	"bullet": "*",
	"dot": "-",
}

_GLYPH_PROBE = "".join(UNICODE_GLYPHS.values())


def glyphs_supported(stream=None) -> bool:
	"""
	Description: Dit si le flux de sortie sait afficher les pictogrammes du rapport.
	Usage: glyphs_supported(sys.stdout).
	Inputs: stream (IO) flux visé, sys.stdout par défaut.
	Outputs: bool vrai quand l'encodage accepte les blocs et les émojis.

	Une console Windows en cp1252 ne sait pas écrire un bloc plein : plutôt que de lever une
	UnicodeEncodeError au moment d'afficher le verdict, le rapport bascule en ASCII.
	"""

	stream = stream if stream is not None else sys.stdout
	encoding = getattr(stream, "encoding", None) or "ascii"
	try:
		_GLYPH_PROBE.encode(encoding)
	except (LookupError, UnicodeEncodeError):
		return False
	return True


def colour_enabled(explicit: bool | None = None, stream=None) -> bool:
	"""
	Description: Décide si la sortie peut porter des couleurs ANSI.
	Usage: colour_enabled(None) pour laisser l'environnement trancher.
	Inputs: explicit (bool | None) choix forcé, stream (IO) flux de sortie visé.
	Outputs: bool vrai si les couleurs sont autorisées.

	Trois règles, dans cet ordre : le choix explicite gagne, puis NO_COLOR, puis le fait
	d'écrire ou non dans un terminal. Un rapport redirigé dans un fichier reste lisible.
	"""

	if explicit is not None:
		return explicit
	if os.environ.get("NO_COLOR"):
		return False
	stream = stream or sys.stdout
	return bool(getattr(stream, "isatty", lambda: False)())


def _paint(text: str, *styles: str, enabled: bool = True) -> str:
	"""
	Description: Applique des styles ANSI à un fragment de texte.
	Usage: _paint("SÛRE", "bold", "green", enabled=True).
	Inputs: text (str) fragment, styles (str) noms de styles, enabled (bool) activation.
	Outputs: str colorée, ou inchangée quand les couleurs sont coupées.
	"""

	if not enabled or not styles:
		return text
	prefix = "".join(_ANSI[style] for style in styles if style in _ANSI)
	return f"{prefix}{text}{_ANSI['reset']}" if prefix else text


paint = _paint


def _gauge(value: float, limit: float, glyphs: dict, width: int = GAUGE_WIDTH) -> str:
	"""
	Description: Dessine une jauge montrant un ratio face à son seuil.
	Usage: _gauge(400.0, 100.0, UNICODE_GLYPHS).
	Inputs: value (float) ratio mesuré, limit (float) seuil, glyphs (dict) jeu de caractères, width (int) largeur.
	Outputs: str faite de blocs pleins et de blocs creux.

	La jauge sature visuellement dès que le seuil est franchi : c'est le seul endroit du
	rapport où l'on voit d'un coup d'œil l'écart entre mesuré et toléré.
	"""

	if limit <= 0:
		return glyphs["empty"] * width
	filled = min(width, round(width * min(value / limit, 1.0)))
	return glyphs["full"] * filled + glyphs["empty"] * (width - filled)


def _field(label: str, value: str, enabled: bool) -> str:
	"""
	Description: Met en forme une ligne libellé/valeur alignée du rapport.
	Usage: _field("entrées", "12", True).
	Inputs: label (str) libellé, value (str) valeur, enabled (bool) couleurs actives.
	Outputs: str de la ligne complète.
	"""

	return f"   {_paint(label.ljust(22), 'dim', enabled=enabled)}{value}"


def _summarise(verdict: Verdict, glyphs: dict) -> str:
	"""
	Description: Résume une archive imbriquée en une ligne.
	Usage: _summarise(child, UNICODE_GLYPHS).
	Inputs: verdict (Verdict) verdict de l'archive fille, glyphs (dict) jeu de caractères.
	Outputs: str courte décrivant le format et le ratio.
	"""

	stats = verdict.stats
	kind = stats.get("kind", "?")
	if "ratio" not in stats:
		return str(kind)
	dot = glyphs["dot"]
	return f"{kind} {dot} ratio {stats['ratio']}x {dot} {human_bytes(stats['total_uncompressed'])}"


def _render_children(verdict: Verdict, enabled: bool, glyphs: dict, depth: int = 0) -> list[str]:
	"""
	Description: Déplie l'arbre des archives imbriquées, une branche par niveau.
	Usage: _render_children(verdict, True, UNICODE_GLYPHS).
	Inputs: verdict (Verdict) nœud courant, enabled (bool) couleurs, glyphs (dict) caractères, depth (int) niveau.
	Outputs: list[str] des lignes à afficher.
	"""

	lines: list[str] = []
	for child in verdict.children:
		pad = "     " + "  " * depth
		mark = glyphs["safe"] if child.safe else glyphs["danger"]
		colour = "green" if child.safe else "red"
		name = _paint(child.stats.get("name", "?"), colour, enabled=enabled)
		summary = _paint(_summarise(child, glyphs), "dim", enabled=enabled)
		lines.append(f"{pad}{mark} {name}  {summary}")
		for reason in child.reasons:
			branch = _paint(glyphs["branch"], "dim", enabled=enabled)
			lines.append(f"{pad}   {branch} {reason}")
		lines.extend(_render_children(child, enabled, glyphs, depth + 1))
	return lines


def render(
	path: str,
	verdict: Verdict,
	*,
	color: bool | None = None,
	limits: Limits | None = None,
	unicode: bool | None = None,
) -> str:
	"""
	Description: Construit le rapport d'inspection lisible dans un terminal.
	Usage: print(render("a.zip", verdict)).
	Inputs: path (str) nom de l'archive, verdict (Verdict) résultat, color (bool | None) couleurs, limits (Limits) seuils affichés en repère, unicode (bool | None) pictogrammes.
	Outputs: str prête à être affichée.
	"""

	enabled = colour_enabled(color)
	glyphs = UNICODE_GLYPHS if (glyphs_supported() if unicode is None else unicode) else ASCII_GLYPHS
	limits = limits or Limits()
	stats = verdict.stats
	rule = _paint(glyphs["rule"] * RULE_WIDTH, "dim", enabled=enabled)

	status = "SÛRE" if verdict.safe else "DANGEREUSE"
	mark = glyphs["safe"] if verdict.safe else glyphs["danger"]
	colour = "green" if verdict.safe else "red"

	title = _paint("ZipGuard", "bold", "cyan", enabled=enabled)
	subtitle = _paint(f"{glyphs['dot']} rapport d'inspection", "dim", enabled=enabled)

	lines = [
		"",
		f"  {title} {subtitle}",
		f"  {rule}",
		"",
		f"   {mark}  {_paint(status, 'bold', colour, enabled=enabled)}   {path}",
	]

	if stats.get("kind"):
		origin = "tailles mesurées" if stats.get("measured") else "tailles déclarées"
		dot = glyphs["dot"]
		detail = f"{stats['kind']} {dot} {origin} {dot} profondeur {stats.get('depth', 0)}"
		lines.append(f"       {_paint(detail, 'dim', enabled=enabled)}")

	if "entries" in stats:
		ratio_line = f"{stats['ratio']}x"
		gauge = _gauge(float(stats["ratio"]), float(limits.max_ratio), glyphs)
		gauge_colour = "red" if stats["ratio"] > limits.max_ratio else "green"
		lines += [
			"",
			_field("entrées", str(stats["entries"]), enabled),
			_field("taille compressée", human_bytes(stats["total_compressed"]), enabled),
			_field("taille décompressée", human_bytes(stats["total_uncompressed"]), enabled),
			_field(
				"ratio",
				f"{ratio_line.ljust(12)}{_paint(gauge, gauge_colour, enabled=enabled)}  "
				f"{_paint(f'seuil {limits.max_ratio}x', 'dim', enabled=enabled)}",
				enabled,
			),
			_field("plus grosse entrée", human_bytes(stats["biggest_entry"]), enabled),
			_field("archives imbriquées", str(stats.get("nested_archives", 0)), enabled),
		]
		if stats.get("links"):
			lines.append(_field("liens symboliques", str(stats["links"]), enabled))

	if verdict.children:
		lines += ["", f"   {_paint('archives imbriquées', 'bold', enabled=enabled)}"]
		lines += _render_children(verdict, enabled, glyphs)

	if verdict.reasons:
		lines += ["", f"   {_paint('raisons du refus', 'bold', 'red', enabled=enabled)}"]
		for reason in verdict.reasons:
			lines.append(f"     {glyphs['bullet']} {reason}")

	lines += ["", f"  {rule}", ""]
	return "\n".join(lines)


def render_json(
	path: str,
	verdict: Verdict,
	*,
	limits: Limits | None = None,
	indent: int | None = 2,
) -> str:
	"""
	Description: Sérialise un verdict pour une chaîne d'intégration continue.
	Usage: print(render_json("a.zip", verdict, indent=None)).
	Inputs: path (str) nom de l'archive, verdict (Verdict) résultat, limits (Limits) seuils appliqués, indent (int | None) mise en forme.
	Outputs: str JSON, compacte sur une ligne quand indent vaut None.

	Le champ schema_version est un contrat : il change si la forme change, pour qu'un script
	branché dessus sache quand il doit être relu.
	"""

	from . import __version__

	payload = {
		"schema_version": SCHEMA_VERSION,
		"tool": "zipguard",
		"version": __version__,
		"archive": path,
		**verdict.as_dict(),
	}
	if limits is not None:
		payload["limits"] = limits.as_dict()

	separators = (",", ":") if indent is None else None
	return json.dumps(payload, ensure_ascii=False, indent=indent, separators=separators)
