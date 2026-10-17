# Journal des modifications

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet
applique le [versionnage sémantique](https://semver.org/lang/fr/).

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
