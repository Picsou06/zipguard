#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CSS="$ROOT/assets/pdf.css"
OUT="$ROOT/docs/pdf"
TMP="$(mktemp -d)"
# Le navigateur qui imprime le PDF est cherché au lieu d'être codé en dur : le script doit
# tourner sur la machine de chacun, pas seulement sur un macOS avec Chrome installé.
find_browser() {
	if [ -n "${CHROME:-}" ] && [ -x "${CHROME}" ]; then
		printf '%s' "$CHROME"
		return 0
	fi
	local candidates=(
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
		"/Applications/Chromium.app/Contents/MacOS/Chromium"
		"/c/Program Files/Google/Chrome/Application/chrome.exe"
		"/c/Program Files (x86)/Google/Chrome/Application/chrome.exe"
		"/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
	)
	local candidate
	for candidate in "${candidates[@]}"; do
		[ -x "$candidate" ] && printf '%s' "$candidate" && return 0
	done
	for candidate in google-chrome google-chrome-stable chromium chromium-browser microsoft-edge; do
		if command -v "$candidate" >/dev/null 2>&1; then
			command -v "$candidate"
			return 0
		fi
	done
	return 1
}

command -v pandoc >/dev/null 2>&1 || {
	echo "pandoc est requis : https://pandoc.org/installing.html" >&2
	exit 1
}

CHROME="$(find_browser)" || {
	echo "Aucun navigateur Chromium trouve. Installe Chrome ou Edge, ou passe CHROME=/chemin/vers/le/binaire." >&2
	exit 1
}
DATE="$(date +%d/%m/%Y)"

trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

printf '<!doctype html><html lang="fr"><head><meta charset="utf-8"><style>\n' > "$TMP/full.html"
cat "$CSS" >> "$TMP/full.html"
printf '\n</style></head><body>\n' >> "$TMP/full.html"

cat >> "$TMP/full.html" <<HTML
<div class="cover-page">
	<div>
		<div class="brand">ZipGuard</div>
	</div>
	<div>
		<div class="shield">🛡️</div>
		<h1 class="title">Documentation</h1>
		<p class="tagline">Comprendre les bombes de décompression pour mieux s'en protéger.</p>
	</div>
	<div class="meta">
		<span>Evan · @Picsou06 &nbsp;&nbsp;•&nbsp;&nbsp; Hamza Karrouchi · @CodeByHaamza</span>
		<span>$DATE</span>
	</div>
</div>

<div class="toc">
	<h1>Sommaire</h1>
	<ol>
		<li><span class="t">Comment ça marche</span><span class="d">— le mécanisme des zip bombs</span></li>
		<li><span class="t">Prévention</span><span class="d">— huit garde fous et la mesure</span></li>
		<li><span class="t">Anatomie du dépôt</span><span class="d">— un adaptateur par format, un seul jeu de seuils</span></li>
	</ol>
</div>
HTML

chapter() {
	local src="$1" tag="$2"
	printf '<section class="chapter"><span class="chapter-tag">%s</span>\n' "$tag" >> "$TMP/full.html"
	pandoc "$src" -t html >> "$TMP/full.html"
	printf '</section>\n' >> "$TMP/full.html"
}

chapter "$ROOT/docs/01-comment-ca-marche.md" "Chapitre 1"
chapter "$ROOT/docs/02-prevention.md" "Chapitre 2"
chapter "$ROOT/docs/03-anatomie.md" "Chapitre 3"

cat >> "$TMP/full.html" <<HTML
<div class="footer">
	<span>ZipGuard — comprendre pour se protéger</span>
	<span>github.com/Picsou06/zipguard</span>
</div>
</body></html>
HTML

PDF="$OUT/ZipGuard-Documentation.pdf"

# Un navigateur Windows lancé depuis Git Bash ne comprend pas un chemin de la forme
# /c/Users/... : il faut le lui traduire, sans quoi il échoue en silence.
to_browser_path() {
	case "$CHROME" in
		*.exe)
			if command -v cygpath >/dev/null 2>&1; then
				cygpath -w "$1"
			else
				printf '%s' "$1"
			fi
			;;
		*) printf '%s' "$1" ;;
	esac
}

rm -f "$PDF"
"$CHROME" --headless=new --disable-gpu --no-pdf-header-footer \
	--virtual-time-budget=6000 \
	--print-to-pdf="$(to_browser_path "$PDF")" \
	"file://$(to_browser_path "$TMP/full.html")" 2>/dev/null

# Le navigateur peut rendre 0 sans rien produire, donc la seule preuve est le fichier.
# Annoncer un succès sans vérifier laisserait un PDF périmé passer pour régénéré.
[ -s "$PDF" ] || {
	echo "Le navigateur n'a produit aucun PDF. Relance avec CHROME=/chemin/vers/le/binaire." >&2
	exit 1
}

echo "OK $PDF ($(wc -c < "$PDF") octets)"
