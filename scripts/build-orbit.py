#!/usr/bin/env python3
"""
Description: Génère assets/orbit.svg, l'emblème animé des contributeurs en orbite autour du logo.
Usage: python scripts/build-orbit.py [--offline]
Inputs: les avatars GitHub des comptes listés dans MEMBERS, téléchargés puis encodés en base64.
Outputs: assets/orbit.svg réécrit sur place.

Les avatars sont embarqués en base64 et non référencés par URL : un SVG affiché dans un
README GitHub est rendu dans une balise img, donc en mode statique sécurisé, où toute
ressource externe est bloquée. Une URL d'avatar y donnerait deux trous à la place des
visages. En contrepartie le fichier pèse quelques dizaines de kilooctets, ce qui reste
négligeable pour un asset de README.
"""

from __future__ import annotations

import argparse
import base64
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "assets" / "orbit.svg"
CACHE = ROOT / "assets" / ".avatars"

MEMBERS = [
	{"handle": "Picsou06", "angle": 0},
	{"handle": "CodeByHaamza", "angle": 180},
]

AVATAR_SIZE = 200
AVATAR_RADIUS = 38
ORBIT_RADIUS = 120
CENTER = (220, 190)
PERIOD = "18s"

SHIELD_PATH = (
	"M110 26 L178 50 V110 C178 150 146 178 110 196 C74 178 42 150 42 110 V50 Z"
)
SHIELD_BOX = {"center": (110, 111), "height": 170}
SHIELD_TARGET_HEIGHT = 112

MIME_BY_MAGIC = {
	b"\x89PNG": "image/png",
	b"\xff\xd8\xff": "image/jpeg",
	b"GIF8": "image/gif",
	b"RIFF": "image/webp",
}


def detect_mime(blob: bytes) -> str:
	"""
	Description: Reconnaît le type d'image réellement reçu, qui n'est pas toujours celui attendu.
	Usage: detect_mime(avatar_bytes).
	Inputs: blob (bytes) début du fichier image.
	Outputs: str type MIME à écrire dans l'URI de données.

	GitHub sert les avatars dans leur format d'origine derrière une URL en .png : celui de
	CodeByHaamza est un JPEG. Annoncer le mauvais type casserait l'affichage.
	"""

	for magic, mime in MIME_BY_MAGIC.items():
		if blob.startswith(magic):
			return mime
	raise ValueError("Format d'avatar inconnu : impossible de deviner le type MIME.")


def fetch_avatar(handle: str, offline: bool) -> bytes:
	"""
	Description: Récupère l'avatar d'un compte GitHub, avec un cache local sur disque.
	Usage: fetch_avatar("Picsou06", offline=False).
	Inputs: handle (str) compte GitHub, offline (bool) interdit l'accès réseau.
	Outputs: bytes de l'image.
	"""

	CACHE.mkdir(parents=True, exist_ok=True)
	cached = CACHE / f"{handle}.bin"

	if cached.is_file():
		return cached.read_bytes()
	if offline:
		raise SystemExit(f"Avatar absent du cache et mode hors ligne demandé : {handle}")

	url = f"https://github.com/{handle}.png?size={AVATAR_SIZE}"
	with urllib.request.urlopen(url, timeout=30) as response:
		blob = response.read()
	cached.write_bytes(blob)
	return blob


def data_uri(blob: bytes) -> str:
	"""
	Description: Encode une image en URI de données prête à poser dans un attribut href.
	Usage: data_uri(avatar_bytes).
	Inputs: blob (bytes) image.
	Outputs: str URI complète.
	"""

	return f"data:{detect_mime(blob)};base64,{base64.b64encode(blob).decode('ascii')}"


def shield_transform() -> str:
	"""
	Description: Calcule la transformation plaçant le blason au centre de l'orbite, à la bonne taille.
	Usage: shield_transform().
	Inputs: aucun, lit SHIELD_BOX et SHIELD_TARGET_HEIGHT.
	Outputs: str valeur de l'attribut transform.
	"""

	scale = SHIELD_TARGET_HEIGHT / SHIELD_BOX["height"]
	cx, cy = CENTER
	sx, sy = SHIELD_BOX["center"]
	return f"translate({cx},{cy}) scale({scale:.4f}) translate({-sx},{-sy})"


def member_node(member: dict, uri: str) -> str:
	"""
	Description: Produit le groupe SVG d'un contributeur : avatar rond, anneau, pseudo.
	Usage: member_node(MEMBERS[0], uri).
	Inputs: member (dict) compte et angle de départ, uri (str) avatar encodé.
	Outputs: str fragment SVG.

	Le groupe extérieur tourne avec l'orbite, le groupe intérieur tourne en sens inverse à
	la même période : le visage et le pseudo restent donc droits pendant tout le tour.
	"""

	handle = member["handle"]
	angle = member["angle"]
	cx, cy = CENTER
	radius = AVATAR_RADIUS
	size = radius * 2
	label = f"@{handle}"
	pill_width = len(label) * 6.3 + 18
	clip = f"avatar-{handle.lower()}"

	return f"""		<g transform="rotate({angle} {cx} {cy})">
			<g transform="translate({cx},{cy - ORBIT_RADIUS})">
				<g>
					<animateTransform attributeName="transform" type="rotate"
						values="{-angle};{-angle - 360}" dur="{PERIOD}" repeatCount="indefinite"/>
					<circle r="{radius + 5}" fill="url(#og)" opacity="0.35"/>
					<circle r="{radius + 2}" fill="url(#og)"/>
					<image href="{uri}" x="{-radius}" y="{-radius}" width="{size}" height="{size}"
						clip-path="url(#{clip})" preserveAspectRatio="xMidYMid slice"/>
					<circle r="{radius}" fill="none" stroke="#ffffff" stroke-opacity="0.85"
						stroke-width="2"/>
					<rect x="{-pill_width / 2:.1f}" y="{radius + 9}" width="{pill_width:.1f}" height="17"
						rx="8.5" fill="#1b2130" fill-opacity="0.82"/>
					<text y="{radius + 21}" text-anchor="middle" font-family="Fira Code, Consolas, monospace"
						font-size="10.5" fill="#e8ecff">{label}</text>
				</g>
			</g>
		</g>"""


def build(offline: bool) -> str:
	"""
	Description: Assemble le SVG complet, axes d'orbite, blason central et contributeurs.
	Usage: build(offline=False).
	Inputs: offline (bool) interdit l'accès réseau.
	Outputs: str contenu du fichier SVG.
	"""

	cx, cy = CENTER
	uris = {member["handle"]: data_uri(fetch_avatar(member["handle"], offline)) for member in MEMBERS}
	nodes = "\n".join(member_node(member, uris[member["handle"]]) for member in MEMBERS)
	clips = "\n".join(
		f'\t\t<clipPath id="avatar-{member["handle"].lower()}">'
		f'<circle r="{AVATAR_RADIUS}"/></clipPath>'
		for member in MEMBERS
	)

	return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 440 380" width="440" height="380"
	role="img" aria-label="Les contributeurs de ZipGuard en orbite autour de l'emblème">
	<defs>
		<linearGradient id="og" x1="0" y1="0" x2="1" y2="1">
			<stop offset="0" stop-color="#7F7FD5"/>
			<stop offset="0.55" stop-color="#86A8E7"/>
			<stop offset="1" stop-color="#91EAE4"/>
		</linearGradient>
		<linearGradient id="sheen" x1="0" y1="0" x2="1" y2="0">
			<stop offset="0" stop-color="#ffffff" stop-opacity="0"/>
			<stop offset="0.5" stop-color="#ffffff" stop-opacity="0.7"/>
			<stop offset="1" stop-color="#ffffff" stop-opacity="0"/>
		</linearGradient>
		<filter id="soft" x="-40%" y="-40%" width="180%" height="180%">
			<feGaussianBlur stdDeviation="7"/>
		</filter>
		<clipPath id="shieldClip"><path d="{SHIELD_PATH}"/></clipPath>
{clips}
	</defs>

	<ellipse cx="{cx}" cy="{cy}" rx="150" ry="{ORBIT_RADIUS}" fill="none" stroke="#86A8E7"
		stroke-opacity="0.5" stroke-width="2" stroke-dasharray="4 8">
		<animate attributeName="stroke-dashoffset" values="0;-120" dur="5s" repeatCount="indefinite"/>
	</ellipse>
	<ellipse cx="{cx}" cy="{cy}" rx="{ORBIT_RADIUS}" ry="150" fill="none" stroke="#91EAE4"
		stroke-opacity="0.34" stroke-width="2" stroke-dasharray="3 10">
		<animate attributeName="stroke-dashoffset" values="0;130" dur="7s" repeatCount="indefinite"/>
	</ellipse>
	<ellipse cx="{cx}" cy="{cy}" rx="150" ry="{ORBIT_RADIUS}" fill="none" stroke="#7F7FD5"
		stroke-opacity="0.24" stroke-width="1.5" stroke-dasharray="1 14"
		transform="rotate(32 {cx} {cy})">
		<animate attributeName="stroke-dashoffset" values="0;-90" dur="9s" repeatCount="indefinite"/>
	</ellipse>

	<circle cx="{cx}" cy="{cy}" r="86" fill="#91EAE4" opacity="0.16" filter="url(#soft)">
		<animate attributeName="r" values="78;92;78" dur="3.2s" repeatCount="indefinite"/>
		<animate attributeName="opacity" values="0.1;0.24;0.1" dur="3.2s" repeatCount="indefinite"/>
	</circle>

	<g transform="{shield_transform()}">
		<path d="{SHIELD_PATH}" fill="url(#og)"/>
		<path d="{SHIELD_PATH}" fill="none" stroke="#ffffff" stroke-opacity="0.55" stroke-width="3"/>
		<g clip-path="url(#shieldClip)">
			<rect x="-200" y="20" width="120" height="200" fill="url(#sheen)" transform="skewX(-18)">
				<animate attributeName="x" values="-200;320" dur="2.8s" repeatCount="indefinite"/>
			</rect>
		</g>
		<text x="110" y="128" text-anchor="middle" font-family="Fira Code, Consolas, monospace"
			font-size="50" font-weight="700" fill="#ffffff">ZG</text>
	</g>

	<g>
		<animateTransform attributeName="transform" type="rotate" values="0 {cx} {cy};360 {cx} {cy}"
			dur="{PERIOD}" repeatCount="indefinite"/>
{nodes}
	</g>

	<circle cx="{cx + 150}" cy="{cy}" r="3.5" fill="#91EAE4">
		<animate attributeName="opacity" values="0.2;1;0.2" dur="1.6s" repeatCount="indefinite"/>
	</circle>
	<circle cx="{cx - 150}" cy="{cy}" r="3.5" fill="#7F7FD5">
		<animate attributeName="opacity" values="1;0.2;1" dur="1.6s" repeatCount="indefinite"/>
	</circle>
</svg>
"""


def main(argv: list[str] | None = None) -> int:
	"""
	Description: Point d'entrée du générateur.
	Usage: python scripts/build-orbit.py.
	Inputs: argv (list[str] | None) arguments.
	Outputs: int code de sortie.
	"""

	parser = argparse.ArgumentParser(description="Génère assets/orbit.svg.")
	parser.add_argument(
		"--offline",
		action="store_true",
		help="Utilise uniquement les avatars déjà en cache dans assets/.avatars.",
	)
	args = parser.parse_args(argv)

	TARGET.parent.mkdir(parents=True, exist_ok=True)
	TARGET.write_text(build(args.offline), encoding="utf-8")
	size = TARGET.stat().st_size
	print(f"{TARGET.relative_to(ROOT)} écrit ({size / 1024:.1f} Kio)")
	return 0


if __name__ == "__main__":
	sys.exit(main())
