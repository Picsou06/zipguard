# Anatomie du dépôt

```text
zipguard/
├── README.md                 présentation animée et guide de prise en main
├── compose.dev.yaml          orchestration de développement
├── compose.prod.yaml         orchestration de production durcie
├── assets/                   emblèmes et captures, tous générés par script
├── docs/                     cours et explications
│   ├── 01-comment-ca-marche.md
│   ├── 02-prevention.md
│   └── 03-anatomie.md
├── samples/                  archives de démonstration générées localement
├── scripts/
│   ├── build-orbit.py        emblème des contributeurs, avatars embarqués
│   ├── build-terminal.py     capture de la sortie réelle de la commande
│   └── build-pdf.sh          dossier PDF mis en page
└── zipguard.app/             service applicatif (code + Docker)
    ├── Dockerfile
    ├── pyproject.toml
    ├── src/zipguard/
    │   ├── formats.py        adaptateurs par format et détection par signature
    │   ├── limits.py         seuils immuables et structure du verdict
    │   ├── scanner.py        inspection récursive et extraction comptée
    │   ├── report.py         rendu texte et sortie JSON
    │   ├── service.py        API HTTP locale et worker jetable
    │   ├── bench.py          corpus synthétique et mesure des garde fous
    │   ├── demo.py           générateur de démonstration borné
    │   └── __main__.py       interface en ligne de commande
    └── tests/                couverture du comportement, 146 tests
```

## L'idée centrale : le scanner ne connaît aucun format

C'est la décision d'architecture dont tout le reste découle. `scanner.py` ne contient pas
une ligne spécifique à ZIP ou à tar : il parle à l'interface `Archive` de `formats.py`, qui
expose partout les mêmes trois choses — l'inventaire des entrées, l'ouverture d'une entrée
en lecture, et la taille compressée de référence.

Conséquence directe : **ajouter un format ne touche pas aux seuils**, et un `tar.xz` passe
exactement les mêmes contrôles qu'un `zip`. Le jour où quelqu'un ajoute `rar`, il écrit un
adaptateur, pas une règle de sécurité.

```text
            ┌─────────────┐
            │  __main__   │  arguments, codes de sortie
            └──────┬──────┘
                   │  Limits
            ┌──────▼──────┐
            │   Scanner   │  seuils, récursion, quota
            └──────┬──────┘
                   │  interface Archive
   ┌───────────────┼───────────────┬─────────────┐
┌──▼───┐    ┌──────▼──────┐  ┌─────▼─────┐  ┌────▼────┐
│ Zip  │    │     Tar     │  │  Stream   │  │ SevenZip│
└──────┘    └─────────────┘  └───────────┘  └─────────┘
manifeste      mesuré          mesuré         manifeste
```

## Le flux d'une inspection

1. `__main__` lit les arguments et construit un objet `Limits` immuable.
2. `formats.open_archive` reconnaît le format **par signature** et rend l'adaptateur.
3. `Scanner.inspect` inventorie les entrées, derrière un plafond de lecture pour les
   formats sans manifeste.
4. Les entrées sont reniflées : celles qui sont elles mêmes des archives deviennent des
   candidates, quel que soit leur nom.
5. Chaque candidate est recopiée dans un fichier temporaire borné, puis inspectée
   récursivement avec le même `Scanner` et le même budget.
6. Chaque seuil dépassé ajoute une raison ; un `Verdict` est rendu, avec ses filles.
7. `report.render` ou `report.render_json` transforme le verdict en sortie.
8. Le code de sortie vaut `0` si l'archive est sûre, `1` sinon, `3` si le fichier est
   introuvable ou illisible : un script peut distinguer un refus d'une panne.

## Le flux d'une extraction

L'extraction ne fait pas confiance au verdict qui vient d'être rendu.

1. L'archive est inspectée. Un verdict défavorable arrête tout.
2. Une passe de validation préalable résout **tous** les chemins et refuse les liens, avant
   la première écriture.
3. L'espace libre est vérifié, et le sera encore périodiquement pendant l'écriture.
4. Chaque entrée est écrite par blocs, chaque bloc recompté face à `max_entry_bytes` et à
   `max_extract_bytes`.
5. Au moindre dépassement, les fichiers déjà écrits sont effacés avant que l'erreur ne
   remonte.

## La frontière de sécurité

Le module `demo.py` plafonne la taille à 100 Mo et ne produit qu'une seule entrée, non
imbriquée, qui se décompresse exactement à la taille annoncée, en `zip` comme en `tar.gz`.
Le corpus de `bench.py` suit la même règle : aucune archive au delà d'un mégaoctet
compressée, aucune imbrication au delà d'un niveau.

Toute la logique offensive est donc absente du dépôt : il n'y a que de la mesure et de la
défense.

## Les limites connues, écrites noir sur blanc

Un outil défensif qui cache ses angles morts n'est pas défendable. Ceux de ZipGuard :

- **7z** passe par un dossier temporaire pour lire une entrée, parce que `py7zr` ne sait
  pas rendre un flux borné. La taille annoncée est vérifiée avant, la taille réelle après :
  un manifeste menteur est détecté une fois l'entrée écrite, pas avant.
- **Lister un `tar` compressé impose de traverser tout le flux.** C'est inhérent au format,
  pas un choix : le plafond de lecture borne le coût, il ne le supprime pas.
- **Les archives chiffrées** ne sont pas inspectables, et ZipGuard ne prétend pas le
  contraire. Les détecter pour les refuser explicitement reste à faire.
- **Le worker du mode service est tué sur un délai**, ce qui borne le temps mais pas la
  mémoire. Un vrai bac à sable système (seccomp, cgroups) serait le cran au dessus.
