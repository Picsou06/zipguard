#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CSS="$ROOT/assets/pdf.css"
OUT="$ROOT/docs/pdf"
TMP="$(mktemp -d)"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
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
		<li><span class="t">Prévention</span><span class="d">— six garde fous et la mesure</span></li>
		<li><span class="t">Anatomie du dépôt</span><span class="d">— le code et la frontière de sécurité</span></li>
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

"$CHROME" --headless=new --disable-gpu --no-pdf-header-footer \
	--virtual-time-budget=4000 \
	--print-to-pdf="$OUT/ZipGuard-Documentation.pdf" \
	"file://$TMP/full.html" >/dev/null 2>&1

echo "✅ $OUT/ZipGuard-Documentation.pdf"
