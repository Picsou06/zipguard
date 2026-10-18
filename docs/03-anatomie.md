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
    │   ├── sources.py        origine des octets : fichier local ou mémoire
    │   ├── remote.py         archive distante lue par plages HTTP, sans disque
    │   ├── formats.py        adaptateurs par format et détection par signature
    │   ├── limits.py         seuils immuables, codes de refus et structure du verdict
    │   ├── scanner.py        inspection récursive et extraction comptée
    │   ├── trust.py          empreintes SHA-256 et liste de confiance
    │   ├── report.py         rendu texte et sortie JSON
    │   ├── sarif.py          rapport SARIF pour l'onglet Sécurité de GitHub
    │   ├── service.py        API HTTP locale et worker jetable
    │   ├── sandbox.py        seccomp, limites de ressources et cgroup du worker
    │   ├── bench.py          corpus synthétique et mesure des garde fous
    │   ├── demo.py           générateur de démonstration borné
    │   └── __main__.py       interface en ligne de commande
    └── tests/                couverture du comportement, 261 tests
```

## L'idée centrale : le scanner ne connaît aucun format

C'est la décision d'architecture dont tout le reste découle. `scanner.py` ne contient pas
une ligne spécifique à ZIP ou à tar : il parle à l'interface `Archive` de `formats.py`, qui
expose partout les mêmes trois choses — l'inventaire des entrées, l'ouverture d'une entrée
en lecture, et la taille compressée de référence.

Conséquence directe : **ajouter un format ne touche pas aux seuils**, et un `tar.xz` passe
exactement les mêmes contrôles qu'un `zip`. Le jour où quelqu'un ajoute `rar`, il écrit un
adaptateur, pas une règle de sécurité.

La même idée s'applique une couche plus bas : les adaptateurs ne connaissent pas l'origine
des octets. Ils demandent un flux à une `Source` — `FileSource` pour un fichier local,
`MemorySource` pour une archive imbriquée lue en mémoire, `RemoteSource` pour une archive
servie en HTTP. C'est ce qui permet d'inspecter une archive distante sans la poser sur le
disque, avec exactement le même code : seule la source dit si l'inspection a le droit
d'écrire un fichier temporaire (`on_disk`) et si son flux sait se déplacer (`seekable`).

```text
            ┌─────────────┐
            │  __main__   │  arguments, codes de sortie
            └──────┬──────┘
                   │  Limits
            ┌──────▼──────┐
            │   Scanner   │  seuils, récursion, quota, confiance
            └──────┬──────┘
                   │  interface Archive
   ┌───────────────┼───────────────┬─────────────┐
┌──▼───┐    ┌──────▼──────┐  ┌─────▼─────┐  ┌────▼────┐
│ Zip  │    │     Tar     │  │  Stream   │  │ SevenZip│
└──┬───┘    └──────┬──────┘  └─────┬─────┘  └────┬────┘
manifeste      mesuré          mesuré         manifeste
   └───────────────┴───────┬───────┴─────────────┘
                           │  interface Source
          ┌────────────────┼────────────────┐
     ┌────▼─────┐    ┌─────▼──────┐   ┌─────▼──────┐
     │  Fichier │    │  Mémoire   │   │  Distante  │
     └──────────┘    └────────────┘   └────────────┘
```

## Le flux d'une inspection

1. `__main__` lit les arguments et construit un objet `Limits` immuable.
2. `formats.open_archive` reconnaît le format **par signature** et rend l'adaptateur.
3. `Scanner.inspect` inventorie les entrées, derrière un plafond de lecture pour les
   formats sans manifeste.
4. Les entrées sont reniflées : celles qui sont elles mêmes des archives deviennent des
   candidates, quel que soit leur nom.
5. Chaque candidate est recopiée dans un tampon borné — un fichier temporaire, ou la
   mémoire quand la source n'a pas le droit d'écrire —, puis inspectée récursivement avec
   le même `Scanner` et le même budget.
6. Chaque seuil dépassé ajoute une raison et son code ; un `Verdict` est rendu, avec ses
   filles. Une archive dont l'empreinte figure dans la liste de confiance s'arrête avant
   l'étape 2, déclarée sûre.
7. `report.render` ou `report.render_json` transforme le verdict en sortie.
8. Le code de sortie vaut `0` si l'archive est sûre, `1` sinon, `3` si le fichier est
   introuvable ou illisible : un script peut distinguer un refus d'une panne.

## Le flux d'une extraction

L'extraction ne fait pas confiance au verdict qui vient d'être rendu.

1. L'archive est recopiée dans un dossier de travail privé, créé dans la destination.
   C'est cette copie qui est inspectée puis extraite. Un verdict défavorable arrête tout.
2. Une passe de validation préalable résout **tous** les chemins, refuse les liens (ou,
   avec `--allow-links`, ceux qui remontent), les doublons et les conflits avec ce qui
   existe déjà, avant la première écriture.
3. L'espace libre est vérifié, et le sera encore périodiquement pendant l'écriture.
4. Chaque entrée est écrite par blocs dans un dossier de préparation, chaque bloc recompté
   face à `max_entry_bytes` et à `max_extract_bytes`.
5. Seulement si tout est passé, l'arborescence préparée est déplacée dans la destination.
6. Dans tous les cas, le dossier de travail est supprimé. Une extraction ratée ne laisse
   donc rien derrière elle, et ne touche à aucun fichier préexistant.

## La frontière de sécurité

Le module `demo.py` plafonne la taille à 100 Mo et ne produit qu'une seule entrée, non
imbriquée, qui se décompresse exactement à la taille annoncée, en `zip` comme en `tar.gz`.
Le corpus de `bench.py` suit la même règle : aucune archive au delà d'un mégaoctet
compressée, aucune imbrication au delà d'un niveau.

Toute la logique offensive est donc absente du dépôt : il n'y a que de la mesure et de la
défense.

## Les limites connues, écrites noir sur blanc

Un outil défensif qui cache ses angles morts n'est pas défendable. Ceux de ZipGuard :

- **7z** passe par un dossier temporaire, ou un tampon mémoire pour une source sans disque,
  pour lire une entrée, parce que `py7zr` ne sait pas rendre un flux borné. La taille
  annoncée est vérifiée avant, la taille réelle après : un manifeste menteur est détecté
  une fois l'entrée décompressée, pas avant.
- **Lister un `tar` compressé impose de traverser tout le flux.** C'est inhérent au format,
  pas un choix : le plafond de lecture borne le coût, il ne le supprime pas.
- **Les archives chiffrées** ne sont pas inspectables : elles sont détectées et refusées,
  pas lues.
- **Le filtre seccomp est une liste de refus**, pas une liste blanche. Il ferme ce qu'un
  analyseur compromis chercherait en premier (réseau, exécution, autres processus, noyau),
  pas tout. Il n'existe que sous Linux x86_64 et aarch64 ; ailleurs, `--sandbox strict`
  refuse d'analyser plutôt que de faire semblant.
- **Le cgroup suppose une délégation** du cgroup v2 à l'utilisateur du service. Sans elle,
  les limites de ressources par processus restent le seul plafond.
- **Une archive de confiance distante** est téléchargée en entier pour calculer son
  empreinte, sous le même plafond de téléchargement.
