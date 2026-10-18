# Journal des modifications

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet
applique le [versionnage sémantique](https://semver.org/lang/fr/).

## [2.1.0]

Une relecture complète a trouvé deux défauts réels, corrigés ici, et le mode service a
été durci.

### Corrigé

- **Une extraction ratée pouvait effacer des fichiers de l'utilisateur.** En cas de
  dépassement de quota, le nettoyage supprimait chaque fichier visé, y compris ceux qui
  existaient déjà dans la destination sous le même nom. L'extraction passe maintenant par
  un dossier de préparation et n'est déplacée dans la destination qu'une fois complète :
  un échec ne touche plus à rien, et ne laisse plus de dossiers vides derrière lui.
- **Une archive 7z contenant un lien symbolique faisait planter le scanner** au lieu de
  rendre un verdict. Les liens 7z sont désormais reconnus comme tels, et les erreurs
  propres à `py7zr` sont rattrapées.
- **Le fichier inspecté pouvait différer du fichier extrait** s'il était remplacé entre les
  deux. L'extraction travaille maintenant sur une copie privée, inspectée puis extraite.
- **Les entrées en double** passaient : la seconde écrasait la première en silence. Elles
  sont refusées, tout comme un nom servant à la fois de fichier et de dossier, ou un
  fichier qui prendrait la place d'un dossier déjà présent.
- Le service pouvait répondre `503` à un client qui enchaînait ses envois, le créneau
  n'étant libéré qu'après la réponse.

### Ajouté

- `zipguard extract --allow-links` : recrée les liens symboliques dont la cible ne fait
  que descendre (relative, sans `..`). Les liens physiques restent refusés.
- `zipguard serve --read-timeout` (30 s par défaut) : un envoi au compte goutte reçoit un
  `408` au lieu de bloquer un thread indéfiniment. Un corps tronqué reçoit un `400`.
- `zipguard serve --max-concurrent` (4 par défaut) : au delà, `503` avec `Retry-After`.
- `zipguard serve --max-memory-mb` (1000 par défaut) : plafond `RLIMIT_AS` sur chaque
  worker. Une analyse qui l'atteint rend un verdict DANGEREUSE ; un worker qui meurt
  sans verdict donne un `500` au lieu d'une réponse absente.
- Couverture des tests dans la CI (seuil de 85 %, tableau dans le résumé du job), et badge
  de couverture publié dans une branche `badges` à chaque passage sur `main`.
- Dossier PDF régénéré avec les nouvelles sections.
- Workflow `release.yml` : publication sur PyPI par étiquette, sans jeton stocké.
- Adresses des deux auteurs dans `pyproject.toml`, affichées sur la page PyPI.

## [2.0.0]

Les six pistes d'évolution de la version 1 sont livrées, et deux failles de détection ont
été trouvées et corrigées en chemin.

### Ajouté

- **Neuf formats** derrière un adaptateur commun : `zip`, `tar`, `tar.gz`, `tar.bz2`,
  `tar.xz`, `gz`, `bz2`, `xz`, et `7z` via l'extra `pip install "zipguard[7z]"`. Le format
  est reconnu par **signature**, jamais par extension.
- **Inspection récursive bornée** : les archives imbriquées sont réellement ouvertes
  jusqu'à `max_depth`, et le verdict porte l'arbre complet de ses filles. Quand la
  profondeur interdit de descendre, le contenu est déclaré invérifiable, donc refusé.
- **Sortie JSON** (`--json`) sur toutes les commandes d'analyse, avec un `schema_version`.
- **Quota d'extraction réel** : `max_extract_bytes` et `min_free_bytes` recomptent les
  octets écrits et surveillent le disque, avec effacement de ce qui a été écrit en cas de
  dépassement.
- **Mode service** (`zipguard serve`) : API HTTP locale analysant chaque envoi dans un
  processus jetable, délai plafonné, écoute sur la boucle locale par défaut.
- **Banc d'essai** (`zipguard bench`) : douze cas synthétiques bornés, un par garde fou,
  mesurant le temps avant refus et vérifiant que chacun tranche comme prévu.
- Sous commandes `extract` et `formats`, codes de sortie documentés (`0` sûre, `1`
  dangereuse, `2` usage, `3` erreur d'exécution).
- Génération `tar.gz` pour les démonstrations (`--format tar.gz`).
- `ruff` en vérification et en formatage, Python 3.13 dans la CI, `SECURITY.md`,
  `.gitattributes`.

### Corrigé

- **Les bombes à entrées recouvrantes n'étaient pas détectées.** Le ratio divisait par la
  somme des tailles compressées annoncées, que cette famille gonfle en faisant pointer
  plusieurs entrées vers le même bloc. Une archive de 28 Ko promettant 20 Mo ressortait
  SÛRE. Le dénominateur est maintenant plafonné par la taille réelle du fichier.
- **Une archive trafiquée faisait planter le scanner** au lieu de rendre un verdict :
  `zipfile.BadZipFile` n'était pas rattrapée. Toutes les erreurs de lecture d'entrée sont
  désormais traitées comme une entrée illisible, qui reste soumise aux seuils.
- **Le support 7z était cassé** : `py7zr` 1.x a retiré la méthode dont dépendait
  l'adaptateur. Il n'avait aucun test ; il en a six.
- **Le rapport plantait sur une console Windows en cp1252**, qui ne sait écrire ni bloc
  plein ni émoji. Un jeu ASCII équivalent prend le relais automatiquement.
- Les liens symboliques sont refusés à l'extraction, dans `tar` comme dans `zip`.
- La protection Zip Slip traite les chemins absolus et les lettres de lecteur Windows, en
  plus de la remontée par deux points.
- `scripts/build-pdf.sh` ne suppose plus un macOS avec Chrome installé.

### Modifié

- Rapport texte entièrement repris : colonnes alignées, jauge de ratio face au seuil,
  arbre des archives imbriquées, couleurs désactivables (`NO_COLOR`, `--no-color`).
- Les assets du README sont générés par script : avatars réels en orbite autour du logo,
  et carte terminal produite en exécutant réellement la commande.

## [1.0.0]

- Scanner d'archives ZIP avec six garde fous et extraction plafonnée.
- Générateur de démonstration borné, interface en ligne de commande, tests, CI, Docker.
- Documentation pédagogique en trois chapitres et dossier PDF.
