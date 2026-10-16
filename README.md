<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:7F7FD5,50:86A8E7,100:91EAE4&height=220&section=header&text=ZipGuard&fontSize=80&fontColor=ffffff&animation=fadeIn&fontAlignY=36&desc=Comprendre%20les%20bombes%20de%20d%C3%A9compression%20pour%20mieux%20s%27en%20prot%C3%A9ger&descAlignY=58&descSize=18" width="100%" alt="ZipGuard" />

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=26&duration=2600&pause=700&color=86A8E7&center=true&vCenter=true&width=720&lines=On+n%27ouvre+jamais+une+archive+les+yeux+ferm%C3%A9s;Mesurer+AVANT+de+d%C3%A9compresser;S%C3%A9curit%C3%A9+%E2%80%A2+P%C3%A9dagogie+%E2%80%A2+Z%C3%A9ro+bombe+embarqu%C3%A9e" alt="typing" />

<br/>

![License](https://img.shields.io/badge/license-MIT-91EAE4?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.10%2B-86A8E7?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/docker-ready-7F7FD5?style=for-the-badge&logo=docker&logoColor=white)

[![CI](https://img.shields.io/github/actions/workflow/status/Picsou06/zipguard/ci.yml?style=for-the-badge&label=CI&logo=githubactions&logoColor=white)](https://github.com/Picsou06/zipguard/actions)
![Stars](https://img.shields.io/github/stars/Picsou06/zipguard?style=for-the-badge&color=86A8E7&logo=github)
![Last commit](https://img.shields.io/github/last-commit/Picsou06/zipguard?style=for-the-badge&color=91EAE4&logo=git&logoColor=white)

<br/><br/>

<img src="https://skillicons.dev/icons?i=python,docker,githubactions,git,bash,md&theme=dark" alt="stack" />

<br/><br/>

<img src="assets/shield.svg" width="620" alt="Emblème ZipGuard animé" />

</div>

<img src="assets/divider.svg" width="100%" alt="" />

## 🎬 Le scan en direct

Le mécanisme, joué en boucle : une archive minuscule qui prétend peser des gigaoctets, et
ZipGuard qui la refuse **avant** d'écrire le moindre octet.

<div align="center">

<img src="assets/ascii-art.svg" width="660" alt="Animation ASCII du fonctionnement" />

<br/><br/>

<img src="assets/simulation.svg" width="760" alt="Simulation d'un scan" />

</div>

---

## ✨ C'est quoi ?

**ZipGuard** est une boîte à outils **éducative et défensive** autour des *bombes de
décompression* (zip bombs). Elle répond à une question simple :

> « Comment un programme peut il ouvrir une archive inconnue sans se faire piéger ? »

Le dépôt n'embarque **aucune bombe prête à l'emploi**. Il contient de la mesure, de la
défense, et un cours. Tout ce qui pourrait servir d'arme en est volontairement absent.

<img src="assets/divider.svg" width="100%" alt="" />

## 🧠 Ce que tu vas apprendre

| Module | Question | Réponse courte |
| :-- | :-- | :-- |
| [Comment ça marche](docs/01-comment-ca-marche.md) | Pourquoi 3 Ko deviennent 10 Go ? | Le ratio de compression des données répétitives |
| [Prévention](docs/02-prevention.md) | Comment s'en protéger ? | Six garde fous + mesure pendant la lecture |
| [Anatomie](docs/03-anatomie.md) | Comment le code est organisé ? | Un service, des seuils immuables, des tests |

> 📘 **Dossier complet en PDF**, mis en page avec la charte graphique :
> [`docs/pdf/ZipGuard-Documentation.pdf`](docs/pdf/ZipGuard-Documentation.pdf)
> — régénérable avec `./scripts/build-pdf.sh` (pandoc + Chrome).

---

## 🚀 Prise en main

```bash
git clone https://github.com/Picsou06/zipguard.git
cd zipguard/zipguard.app
pip install .
```

### Inspecter une archive (le cœur défensif)

```bash
zipguard scan une_archive.zip
```

```
  ✅  ZipGuard — rapport d'inspection
      Archive : une_archive.zip
      Verdict : SÛRE

      Statistiques
        entrées              : 1
        taille compressée    : 1.2 KiB
        taille décompressée  : 480.0 KiB
        ratio                : 400.0x
```

Un ratio trop élevé, une taille démesurée ou des archives imbriquées ? Le verdict passe à
**DANGEREUSE**, l'extraction est refusée, et le code de sortie vaut `1`.

### Démonstration bornée (illustrer le ratio, sans danger)

```bash
zipguard demo samples/demo.zip --text zizi --mb 10
```

Archive **plafonnée à 100 Mo**, non imbriquée, qui se décompresse exactement à la taille
annoncée. Elle montre la puissance de la compression des données répétitives sans jamais
pouvoir servir d'arme.

## 🐳 Docker

```bash
# développement (code monté en lecture seule)
docker compose -f compose.dev.yaml run --rm zipguard scan /samples/demo.zip

# production (conteneur durci, lecture seule, sans privilèges)
docker compose -f compose.prod.yaml build
```

<img src="assets/divider.svg" width="100%" alt="" />

## 🛡️ Les six garde fous

<div align="center">

| # | Garde fou | Champ |
| :-: | :-- | :-- |
| 1 | Taille décompressée totale plafonnée | `max_total_bytes` |
| 2 | Taille par entrée plafonnée | `max_entry_bytes` |
| 3 | Ratio de compression maximal | `max_ratio` |
| 4 | Nombre d'entrées maximal | `max_entries` |
| 5 | Profondeur d'imbrication maximale | `max_depth` |
| 6 | Lecture plafonnée pendant l'extraction | `safe_extract` |

</div>

Détails et justifications dans [docs/02-prevention.md](docs/02-prevention.md).

---

## 👥 L'équipe

<div align="center">

<img src="assets/orbit.svg" width="560" alt="Les deux profils en orbite autour de ZipGuard" />

<br/>

<table>
<tr>
<td align="center" width="50%">
<a href="https://github.com/Picsou06">
<img src="https://github.com/Picsou06.png" width="110" style="border-radius:50%" alt="Evan" /><br/>
<b>Evan</b> · <code>@Picsou06</code>
</a><br/>
<sub>Architecture & moteur de mesure</sub>
</td>
<td align="center" width="50%">
<a href="https://github.com/CodeByHaamza">
<img src="https://github.com/CodeByHaamza.png" width="110" style="border-radius:50%" alt="Hamza" /><br/>
<b>Hamza Karrouchi</b> · <code>@CodeByHaamza</code>
</a><br/>
<sub>Extraction sûre & pédagogie</sub>
</td>
</tr>
</table>

<table>
<tr>
<td>
<img src="https://github-readme-stats.vercel.app/api?username=Picsou06&show_icons=true&hide_border=true&title_color=7F7FD5&icon_color=91EAE4&text_color=808080&bg_color=00000000" width="400" alt="Stats Evan" />
</td>
<td>
<img src="https://github-readme-stats.vercel.app/api?username=CodeByHaamza&show_icons=true&hide_border=true&title_color=7F7FD5&icon_color=91EAE4&text_color=808080&bg_color=00000000" width="400" alt="Stats Hamza" />
</td>
</tr>
</table>

</div>

## 🗺️ Répartition du travail

Un partage pensé pour être **équilibré et complémentaire** : chacun porte une moitié
cohérente du projet, de la conception à la vérification.

| Domaine | Evan · `@Picsou06` | Hamza · `@CodeByHaamza` |
| :-- | :--: | :--: |
| Modèle de menace & conception | ● | ○ |
| Moteur de mesure (ratio, seuils, verdict) | ● | ○ |
| Interface en ligne de commande | ● | ○ |
| Intégration Docker & CI/CD | ● | ○ |
| Extraction plafonnée & protection Zip Slip | ○ | ● |
| Générateur de démonstration borné | ○ | ● |
| Suite de tests & couverture | ○ | ● |
| Documentation pédagogique (`docs/`) | ○ | ● |

<sub>● responsable principal · ○ relecture et co-conception. Chaque ligne a été relue à deux, d'où le co-auteur systématique sur les commits.</sub>

<img src="assets/divider.svg" width="100%" alt="" />

## 💡 Idées d'évolution

- 🟢 **Support `tar.gz` et `7z`** en appliquant les mêmes seuils.
- 🟢 **Sortie JSON** (`--json`) pour brancher le scanner dans une chaîne CI.
- 🟡 **Inspection récursive bornée** des archives imbriquées jusqu'à `max_depth`.
- 🟡 **Quota disque réel** pendant l'extraction via un répertoire surveillé.
- 🔴 **Mode service** (petite API HTTP) analysant un flux dans un worker isolé.
- 🔴 **Banc d'essai** mesurant le temps avant refus sur un corpus synthétique.

## 🧪 Tests

```bash
cd zipguard.app
pip install -r requirements-dev.txt
pytest -q
```

La CI rejoue cette suite sur Python 3.10, 3.11 et 3.12, puis construit l'image Docker.

## ⚖️ Éthique

Ce projet est **défensif et pédagogique**. Il explique un mécanisme d'attaque uniquement
pour apprendre à le détecter et à le neutraliser. Aucune charge offensive n'est fournie.
À utiliser sur tes propres systèmes et dans un cadre d'apprentissage.

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:91EAE4,50:86A8E7,100:7F7FD5&height=140&section=footer&text=Mesurer%20avant%20de%20d%C3%A9compresser&fontSize=22&fontColor=ffffff&fontAlignY=70" width="100%" alt="footer" />

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=15&duration=3000&pause=800&color=7F7FD5&center=true&vCenter=true&width=600&lines=MIT+%C2%A9+2026+%E2%80%94+%40Picsou06+%26+%40CodeByHaamza;Fait+avec+%F0%9F%9B%A1%EF%B8%8F+et+beaucoup+de+curiosit%C3%A9" alt="footer-typing" />

</div>
