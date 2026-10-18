<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:7F7FD5,50:86A8E7,100:91EAE4&height=220&section=header&text=ZipGuard&fontSize=80&fontColor=ffffff&animation=fadeIn&fontAlignY=36&desc=Comprendre%20les%20bombes%20de%20d%C3%A9compression%20pour%20mieux%20s%27en%20prot%C3%A9ger&descAlignY=58&descSize=18" width="100%" alt="ZipGuard" />

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=26&duration=2600&pause=700&color=86A8E7&center=true&vCenter=true&width=720&lines=On+n%27ouvre+jamais+une+archive+les+yeux+ferm%C3%A9s;Mesurer+AVANT+de+d%C3%A9compresser;S%C3%A9curit%C3%A9+%E2%80%A2+P%C3%A9dagogie+%E2%80%A2+Z%C3%A9ro+bombe+embarqu%C3%A9e" alt="typing" />

<br/>

![License](https://img.shields.io/badge/license-MIT-91EAE4?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.10%2B-86A8E7?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/docker-ready-7F7FD5?style=for-the-badge&logo=docker&logoColor=white)
![Formats](https://img.shields.io/badge/formats-9-86A8E7?style=for-the-badge)

[![CI](https://img.shields.io/github/actions/workflow/status/Picsou06/zipguard/ci.yml?style=for-the-badge&label=CI&logo=githubactions&logoColor=white)](https://github.com/Picsou06/zipguard/actions)
![Stars](https://img.shields.io/github/stars/Picsou06/zipguard?style=for-the-badge&color=86A8E7&logo=github)
[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FPicsou06%2Fzipguard%2Fbadges%2Fcoverage.json&style=for-the-badge&logo=pytest&logoColor=white)](https://github.com/Picsou06/zipguard/actions/workflows/ci.yml)
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

### Et la vraie sortie, sans retouche

Celle ci n'est pas une capture d'écran faite à la main : elle est **produite en exécutant
réellement la commande**, par [`scripts/build-terminal.py`](scripts/build-terminal.py).
Un README qui recopie une sortie à la main finit toujours par mentir.

<div align="center">

<img src="assets/scan-reel.svg" width="820" alt="Sortie réelle de zipguard scan" />

</div>

L'archive du dessus est le cas intéressant : **son propre ratio est de 1.0x**, parfaitement
innocent. Le danger est un niveau plus bas, dans une entrée appelée `notes.txt` qui est en
fait une archive. C'est exactement ce qu'un scanner non récursif laisserait passer.

<img src="assets/divider.svg" width="100%" alt="" />

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
| [Prévention](docs/02-prevention.md) | Comment s'en protéger ? | Onze garde fous + mesure pendant la lecture |
| [Anatomie](docs/03-anatomie.md) | Comment le code est organisé ? | Un adaptateur par format, un seul jeu de seuils |

> 📘 **Dossier complet en PDF**, mis en page avec la charte graphique :
> [`docs/pdf/ZipGuard-Documentation.pdf`](docs/pdf/ZipGuard-Documentation.pdf)
> — régénérable avec `./scripts/build-pdf.sh` (pandoc + un navigateur Chromium).

---

## 🚀 Prise en main

```bash
git clone https://github.com/Picsou06/zipguard.git
cd zipguard/zipguard.app
pip install .

# avec le support 7z, qui demande une dépendance externe
pip install ".[7z]"
```

### Inspecter une archive (le cœur défensif)

```bash
zipguard scan une_archive.zip
```

```
  ZipGuard · rapport d'inspection
  ────────────────────────────────────────────────────────────────────

   ✅  SÛRE   rapport.zip
       zip · tailles déclarées · profondeur 0

   entrées               2
   taille compressée     468.9 KiB
   taille décompressée   468.8 KiB
   ratio                 1.0x        ░░░░░░░░░░░░░░░░░░░░░░  seuil 100.0x
   plus grosse entrée    468.8 KiB
   archives imbriquées   0

  ────────────────────────────────────────────────────────────────────
```

Un ratio trop élevé, une taille démesurée, trop d'entrées ou une archive imbriquée
dangereuse ? Le verdict passe à **DANGEREUSE**, l'extraction est refusée, et le code de
sortie vaut `1`.

### Les commandes

| Commande | Ce qu'elle fait |
| :-- | :-- |
| `zipguard scan CIBLE...` | Inspecte une archive, plusieurs, un dossier entier ou une URL, sans rien écrire sur le disque |
| `zipguard extract ARCHIVE DEST` | Extrait une archive jugée sûre, en recomptant chaque octet |
| `zipguard demo FICHIER` | Fabrique une démonstration bornée, en `zip` ou `tar.gz` |
| `zipguard serve` | Expose le scanner en petit service HTTP local |
| `zipguard bench` | Mesure le temps que met chaque garde fou à trancher |
| `zipguard formats` | Liste les formats pris en charge |
| `zipguard fingerprint ARCHIVE...` | Affiche les empreintes SHA-256, prêtes pour une liste `--trust` |

Toutes les commandes d'analyse acceptent `--json`, et les seuils se règlent en ligne de
commande : `--max-ratio`, `--max-total-mb`, `--max-entry-mb`, `--max-entries`,
`--max-depth`, plus `--max-extract-mb`, `--min-free-mb` et `--allow-links` pour
l'extraction. `scan` ajoute `--sarif`, `--exit-zero` et les réglages de l'inspection
distante ; `scan`, `extract` et `serve` acceptent `--trust FICHIER`.

Avec plusieurs cibles, ou un dossier, `scan` enchaîne les rapports, et `--json` rend une
liste des mêmes objets. Un dossier est parcouru sans suivre les liens, en sautant `.git`,
`node_modules` et consorts ; chaque fichier reconnu comme archive **par sa signature** est
inspecté.

### Codes de sortie

| Code | Signification |
| :-: | :-- |
| `0` | Opération réussie, archive jugée sûre |
| `1` | Archive jugée dangereuse, ou extraction refusée |
| `2` | Erreur d'utilisation de la ligne de commande |
| `3` | Erreur d'exécution : fichier introuvable, illisible, plafond de démo |

Une archive introuvable ne se déguise donc pas en verdict dangereux : un script peut
distinguer **un refus** d'**une panne**.

### Brancher dans une chaîne d'intégration

```bash
zipguard scan livraison.zip --json | jq '.safe, .reasons'
```

```json
{
  "schema_version": 1,
  "tool": "zipguard",
  "version": "2.2.0",
  "archive": "livraison.zip",
  "safe": false,
  "verdict": "DANGEREUSE",
  "reasons": ["Archive imbriquée dangereuse — notes.txt : Ratio de compression anormal : 1027.2x > 20.0x."],
  "codes": ["nested"],
  "stats": { "kind": "zip", "entries": 2, "ratio": 1.0, "nested_archives": 1 },
  "children": [ { "safe": false, "stats": { "name": "notes.txt", "kind": "zip", "ratio": 1027.22 } } ],
  "limits": { "max_ratio": 20.0 }
}
```

Le champ `schema_version` est un contrat : il changera si la forme change, pour qu'un
script branché dessus sache quand il doit être relu. Ajouter un champ ne casse personne et
ne le fait pas bouger.

Chaque raison porte un **code stable** dans `codes`, dans le même ordre : `ratio`,
`total_size`, `entry_size`, `too_many_entries`, `read_cap`, `encrypted`, `nested`,
`nested_cut`, `depth`, `nested_budget`, `download_cap`, `memory`, `unreadable`,
`unsupported`. Les phrases sont faites pour être lues et peuvent changer ; les codes sont
faits pour être triés par une machine.

### Les refus dans l'onglet Sécurité de GitHub (SARIF)

```bash
zipguard scan . --sarif --exit-zero > zipguard.sarif
```

Le rapport [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
porte une règle par code de refus, avec sa gravité, et un résultat par raison, rattaché au
fichier de l'archive. Dans un workflow :

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with:
      python-version: "3.12"
  - run: pip install zipguard
  - run: zipguard scan . --sarif --exit-zero > zipguard.sarif
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: zipguard.sarif
      category: zipguard
```

`--exit-zero` laisse le job continuer jusqu'à la publication du rapport : c'est l'onglet
Sécurité, pas le statut du job, qui porte les refus. Sans lui, le code de sortie vaut `1`
dès qu'une archive est dangereuse, ce qui convient pour bloquer une livraison.

### Archives de confiance

Un jeu de données légitime peut avoir un ratio qui fait peur : un CSV de zéros se
compresse aussi bien qu'une bombe. Plutôt que de relâcher les seuils pour tout le monde,
on déclare ces archives **par leur empreinte** :

```bash
zipguard fingerprint donnees/*.tar.gz > confiance.txt    # même format que sha256sum
zipguard scan donnees/ --trust confiance.txt
```

Une archive dont l'empreinte SHA-256 figure dans la liste est déclarée sûre sans être
inspectée ; un seul octet changé et elle redevient une inconnue. La confiance porte sur le
**verdict**, pas sur l'**écriture** : `extract` applique toujours ses quotas, et n'extrait
jamais une entrée chiffrée. La liste se lit telle que `sha256sum` l'écrit ; une ligne mal
formée est une erreur, jamais une ligne ignorée en silence.

### Inspecter une archive distante sans la télécharger

```bash
zipguard scan https://exemple.org/livraison.zip
```

L'archive est lue par plages HTTP et **jamais posée sur le disque**, archives imbriquées
comprises, qui sont lues en mémoire. Pour un zip, le manifeste et l'en-tête de chaque
entrée suffisent : une roue `numpy` de 15,6 Mio, mille fichiers et cinq archives
imbriquées, est jugée en moins d'une seconde après 3,5 Mio téléchargés.

| Option | Défaut | Rôle |
| :-- | :-- | :-- |
| `--max-download-mb` | 200 | Coupe toute lecture au delà, et devient la raison du refus |
| `--max-buffer-mb` | 64 | Mémoire accordée à une archive imbriquée lue sans disque |
| `--remote-timeout` | 30 s | Délai de chaque requête |

Un `tar` ou un flux compressé distant est lu dans l'ordre, derrière les mêmes plafonds.
Sont refusés, avec une raison claire : un serveur qui n'annonce pas la taille du fichier
(c'est le dénominateur du ratio), un serveur qui recompresse à la volée, et un zip ou un
7z sur un serveur qui ne sait pas servir de plages, puisque leur manifeste est en fin de
fichier.

### Démonstration bornée (illustrer le ratio, sans danger)

```bash
zipguard demo samples/demo.zip --mb 10
zipguard demo samples/demo.tar.gz --format tar.gz --mb 10
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

## 📦 Neuf formats, un seul jeu de seuils

Le scanner ne connaît aucun format : il parle à un adaptateur commun. Un `tar.xz` passe
donc exactement les mêmes contrôles qu'un `zip`.

| Format | Ce que ZipGuard peut croire |
| :-- | :-- |
| `zip` | Un manifeste complet, vérifié ensuite pendant l'extraction |
| `7z` | Un manifeste, via la dépendance optionnelle `py7zr` |
| `tar`, `tar.gz`, `tar.bz2`, `tar.xz` | Rien : les tailles sont **mesurées** en lisant |
| `gz`, `bz2`, `xz` | Rien : un flux simple, mesuré lui aussi |

> **Le format est reconnu par sa signature, jamais par son extension.** Une bombe renommée
> en `notes.txt` est traitée comme une bombe.

### Le piège du dénominateur

Diviser la taille décompressée par la **somme des tailles compressées annoncées** paraît
naturel, et c'est une erreur. Dans une bombe à *entrées recouvrantes*, plusieurs entrées du
répertoire central pointent vers le même bloc compressé : la somme est gonflée autant de
fois qu'il y a de références, donc le ratio apparent est divisé d'autant.

Une archive de **28 Ko promettant 20 Mo** passait ainsi pour sûre, avec un ratio affiché de
50x là où la réalité était 692x. ZipGuard plafonne désormais le dénominateur par la taille
réelle du fichier sur le disque, qui ne ment pas.

Pour les formats sans manifeste, ZipGuard change de méthode mais pas de règle. Un `tar` ne
déclare pas de taille compressée par entrée, et le pied de page `gzip` annonce une taille
*modulo 4 Gio*, donc mensongère par construction au delà. La seule valeur digne de
confiance est celle que l'on compte soi même : l'inventaire se fait derrière un compteur
qui coupe au seuil, ce qui transforme **l'inventaire lui même en garde fou**.

<img src="assets/divider.svg" width="100%" alt="" />

## 🛡️ Les onze garde fous

<div align="center">

| # | Garde fou | Champ | Quand il agit |
| :-: | :-- | :-- | :-- |
| 1 | Taille décompressée totale plafonnée | `max_total_bytes` | inspection |
| 2 | Taille par entrée plafonnée | `max_entry_bytes` | inspection + écriture |
| 3 | Ratio de compression maximal | `max_ratio` | inspection |
| 4 | Nombre d'entrées maximal | `max_entries` | inspection |
| 5 | Profondeur d'imbrication maximale | `max_depth` | inspection récursive |
| 6 | Budget d'inspection des imbriquées | `max_nested_scans` | inspection récursive |
| 7 | Quota d'octets réellement écrits | `max_extract_bytes` | écriture |
| 8 | Marge d'espace disque libre exigée | `min_free_bytes` | écriture |
| 9 | Archive chiffrée refusée | — | inspection + écriture |
| 10 | Mémoire accordée à une imbriquée lue sans disque | `max_buffer_bytes` | inspection distante |
| 11 | Plafond de téléchargement | `max_download_bytes` | inspection distante |

</div>

Une **archive chiffrée** est refusée : ses tailles annoncées ne peuvent pas être
vérifiées, et une archive imbriquée n'y serait pas vue. ZipGuard la repère par le drapeau
de chiffrement de chaque entrée zip (historique comme AES) et par `py7zr` pour un 7z, y
compris quand même la liste des entrées est chiffrée. Avant la version 2.2, un zip chiffré
faisait planter le scanner.

Trois des garde fous de la version 2 bouchent chacun un trou précis :

- **`max_depth` ne se contente plus de refuser l'imbrication** : ZipGuard descend vraiment
  dans les archives filles et rend l'arbre complet des verdicts. Quand la profondeur
  interdit de descendre, le contenu est déclaré *invérifiable*, donc refusé — un défenseur
  ne fait pas confiance à ce qu'il n'a pas pu lire.
- **`max_nested_scans`** borne le travail total. Sans lui, une archive contenant dix mille
  archives vides suffirait à monter un déni de service : par le travail, pas par la taille.
- **`max_extract_bytes` et `min_free_bytes`** s'appliquent pendant l'écriture. Le verdict
  ne suffit pas, parce qu'un manifeste peut mentir : chaque octet écrit est recompté, et
  un dépassement **annule toute l'extraction**.

L'extraction est **tout ou rien**. L'archive est d'abord recopiée dans un dossier privé, et
c'est cette copie qui est inspectée puis extraite : le fichier ne peut plus changer entre
le verdict et l'écriture. Tout est ensuite écrit dans un dossier de préparation, et rien
n'arrive dans la destination tant que la dernière entrée n'est pas passée. Un échec ne
touche donc jamais aux fichiers qui s'y trouvaient déjà.

Tous les chemins sont validés *avant* la première écriture : la protection Zip Slip traite
les trois pièges classiques (chemin absolu, lettre de lecteur Windows, remontée par deux
points), les entrées en double sont refusées, tout comme un fichier qui prendrait la place
d'un dossier existant. Les liens symboliques sont refusés par défaut ; avec
`--allow-links`, seuls ceux dont la cible descend sous leur propre dossier, sans `..` ni
chemin absolu, sont recréés. Les liens physiques ne le sont jamais.

Détails et justifications dans [docs/02-prevention.md](docs/02-prevention.md).

<img src="assets/divider.svg" width="100%" alt="" />

## 🌐 Mode service

```bash
zipguard serve --port 8723
curl --data-binary @suspect.zip http://127.0.0.1:8723/scan | jq .safe
```

| Route | Réponse |
| :-- | :-- |
| `GET /health` | État du service et version |
| `GET /limits` | Les seuils réellement appliqués |
| `POST /scan` | L'archive en octets bruts, le verdict en JSON |

Chaque envoi est analysé dans un **processus jetable**. Un service qui déballe des archives
inconnues dans son propre processus se fait tuer par la première qui épuise la mémoire ou
tourne trop longtemps ; ici le dégât est plafonné à un worker perdu, et un délai dépassé
devient une réponse `504`.

L'écoute est sur la **boucle locale par défaut**, pas sur toutes les interfaces : un service
pareil ne s'expose pas au réseau sans que quelqu'un l'ait décidé. L'envoi est plafonné et
refusé sur la seule base de son en tête `Content-Length`, donc avant d'avoir lu un octet,
et le fichier reçu ne survit jamais à la requête.

Trois garde fous protègent le service lui même :

| Option | Défaut | Contre quoi |
| :-- | :-- | :-- |
| `--read-timeout` | 30 s | Un client qui envoie son corps au compte goutte (`408`) |
| `--max-concurrent` | 4 | Cent envois simultanés, donc cent workers (`503` au delà) |
| `--max-memory-mb` | 1000 | Une analyse qui fait gonfler la mémoire : verdict DANGEREUSE |

Le plafond mémoire s'appuie sur `RLIMIT_AS` et ne s'applique qu'au worker, sous Linux et
macOS ; `0` le désactive.

### Le bac à sable du worker

Avant de lire le moindre octet de l'archive, le worker s'enferme :

| Couche | Ce qu'elle interdit |
| :-- | :-- |
| **seccomp** (Linux x86_64 et aarch64) | Réseau, lancement de programmes (`execve`), `fork`, `ptrace`, accès à la mémoire d'autres processus, montages, modules noyau, `bpf`, espaces de noms, `io_uring` : refusés avec `EPERM` |
| **no_new_privs** | Regagner des privilèges par un exécutable setuid |
| **Limites de ressources** | Mémoire, temps processeur, taille de fichier écrit, descripteurs ouverts, fichiers core ; les limites dures descendent avec les souples, le worker ne peut pas les relever |
| **cgroup v2** (`--cgroup-root`) | Un cgroup jetable par worker : `memory.max`, `pids.max`, et `cgroup.kill` sur délai dépassé |

```bash
zipguard serve --sandbox strict --cgroup-root /sys/fs/cgroup/zipguard
```

`--sandbox auto` (par défaut) pose ce que le système permet et le dit ; `strict` refuse
d'analyser s'il manque un seul élément (`500`) ; `off` ne pose rien. `GET /health` décrit
le bac à sable configuré, et chaque réponse de `/scan` rapporte, dans `sandbox`, ce qui
était **réellement** en place pour cette analyse.

Le filtre seccomp est une **liste de refus**, pas une liste blanche : l'interpréteur Python
fait des centaines d'appels légitimes qui varient d'une version à l'autre, et une liste
blanche trop courte tuerait le worker sur une machine non testée. Elle vise ce qu'un
analyseur compromis chercherait en premier. Le cgroup suppose qu'un administrateur ait
délégué un sous arbre à l'utilisateur du service ; c'est une option, jamais un prérequis.

<img src="assets/divider.svg" width="100%" alt="" />

## ⏱️ Banc d'essai

```bash
zipguard bench
```

```
  cas                       garde fou           format    verdict           temps          lu
  ---------------------------------------------------------------------------------------------
  benigne.zip               aucun               zip       SÛRE            0.37 ms      35.0 o
  ratio.zip                 ratio               zip       REFUSÉE         0.15 ms     3.8 MiB
  entrees.zip               max_entries         zip       REFUSÉE        10.26 ms     500.0 o
  entree-unique.zip         max_entry_bytes     zip       REFUSÉE         0.13 ms     3.8 MiB
  total.zip                 max_total_bytes     zip       REFUSÉE         0.10 ms     3.8 MiB
  imbriquee.zip             imbrication         zip       REFUSÉE         1.32 ms     3.9 KiB
  imbriquee-profondeur.zip  max_depth           zip       REFUSÉE         0.09 ms     3.9 KiB
  mesure.tar.gz             ratio_mesure        tar.gz    REFUSÉE         5.41 ms     3.8 MiB
  lecture-coupee.tar.gz     plafond_de_lecture  tar.gz    REFUSÉE         0.92 ms   490.0 KiB
  flux.txt.gz               flux_compresse      gz        REFUSÉE         3.07 ms     3.8 MiB
  recouvrement.zip          recouvrement        zip       REFUSÉE         0.37 ms    19.1 MiB
  chiffree.zip              chiffrement         zip       REFUSÉE         0.06 ms       7.0 o
  confiance.zip             confiance           zip       SÛRE            0.03 ms       0.0 o
  pas-une-archive.txt       format              inconnu   REFUSÉE         0.05 ms       0.0 o
  ---------------------------------------------------------------------------------------------
  14 cas, 22.3 ms au total, 0 verdict(s) inattendu(s)
```

La ligne à lire est `lecture-coupee.tar.gz` : **490 Kio lus sur 3,8 Mio** avant que le
plafond ne coupe. C'est toute la thèse du projet en un chiffre — refuser sans avoir tout
déballé.

Les deux cas de la version 2.2 se lisent ensemble : `chiffree.zip` est refusée sans qu'un
seul octet de son contenu soit lu, et `confiance.zip`, dont le ratio ferait refuser
n'importe quelle bombe, passe en quelques centièmes de milliseconde parce que son
empreinte figure dans la liste de confiance.

Le corpus est synthétique, borné, et reconstruit à chaque lancement : aucune archive ne
dépasse un mégaoctet compressée, aucune ne s'imbrique au delà d'un niveau. Le banc **mesure
une défense, il ne fabrique pas une arme**. Au passage, il vérifie que chaque garde fou rend
bien le verdict attendu, ce qui en fait un test de bout en bout autant qu'un chronomètre.

<img src="assets/divider.svg" width="100%" alt="" />

## 👥 L'équipe

<div align="center">

<img src="assets/orbit.svg" width="440" alt="Les deux contributeurs en orbite autour de l'emblème ZipGuard" />

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

<sub>● responsable principal · ○ relecture et co-conception. Chaque ligne a été relue à deux, d'où le co-auteur systématique sur les commits. Les modules de la version 2 — adaptateurs de format, inspection récursive, quota d'extraction, mode service, banc d'essai — ont été construits à quatre mains.</sub>

<img src="assets/divider.svg" width="100%" alt="" />

## 💡 Idées d'évolution

Les six pistes de la version 1 sont **toutes livrées** :

| Piste | État |
| :-- | :-- |
| Support `tar.gz` et `7z` avec les mêmes seuils | ✅ neuf formats, plus `tar.bz2`, `tar.xz`, `gz`, `bz2`, `xz` |
| Sortie JSON pour brancher le scanner dans une CI | ✅ `--json` sur toutes les commandes, avec `schema_version` |
| Inspection récursive bornée jusqu'à `max_depth` | ✅ arbre complet des verdicts, budget d'inspection |
| Quota disque réel pendant l'extraction | ✅ octets recomptés + marge de disque libre, nettoyage au dépassement |
| Mode service analysant un flux dans un worker isolé | ✅ API HTTP locale, processus jetable, délai plafonné |
| Banc d'essai mesurant le temps avant refus | ✅ quatorze cas, un par garde fou, verdicts vérifiés |

Les cinq pistes de la version 2 sont livrées à leur tour dans la 2.2 :

| Piste | État |
| :-- | :-- |
| 🟢 Signatures de confiance par empreinte | ✅ `fingerprint`, `--trust`, format `sha256sum`, archives imbriquées comprises |
| 🟢 Rapport SARIF pour l'onglet Sécurité | ✅ `scan --sarif`, une règle par code de refus, dossiers entiers |
| 🟡 Inspection en flux d'une archive distante | ✅ lecture par plages HTTP, zéro écriture disque, plafond de téléchargement |
| 🟡 Détection des archives chiffrées | ✅ zip (historique et AES) et 7z, y compris en-têtes chiffrés |
| 🔴 Bac à sable système du worker | ✅ seccomp, no_new_privs, limites de ressources, cgroup v2 optionnel |

La suite, pour qui veut continuer :

- 🟢 **Action GitHub prête à l'emploi** (`uses: Picsou06/zipguard@v2`) qui scanne le dépôt
  et publie le SARIF en une ligne.
- 🟡 **Inspection en flux pour `scan -`**, une archive lue sur l'entrée standard.
- 🟡 **Liste blanche seccomp** générée en traçant les appels réels du worker, plus stricte
  que la liste de refus actuelle.
- 🔴 **Formats `rar` et `zstd`**, derrière le même adaptateur et les mêmes seuils.

## 🧪 Tests

```bash
cd zipguard.app
pip install -r requirements-dev.txt
pytest -q                         # 261 tests
pytest -q --cov=zipguard          # avec la couverture
ruff check .                      # style et erreurs courantes
```

La CI rejoue cette suite sur Python 3.10 à 3.13, exige au moins 85 % de couverture et
l'affiche dans le résumé du job, vérifie le style, puis construit l'image Docker. À chaque
passage sur `main`, le pourcentage est écrit dans la branche `badges`, que lit le badge
du haut de page : aucun service externe.

### Publier une version

[PyPI](https://pypi.org) est l'index officiel des paquets Python : c'est là que `pip` va
chercher ce qu'on lui demande d'installer. Une fois publié, ZipGuard s'installe sans
cloner le dépôt :

```bash
pip install zipguard
pip install "zipguard[7z]"   # avec le support 7z
```

La page PyPI affiche les deux auteurs déclarés dans `pyproject.toml`, avec leur adresse.
Après la première publication, celui qui a créé le projet sur PyPI ajoute l'autre comme
*Owner* (*Manage → Collaborators*), pour que les deux puissent gérer les versions.

Le workflow [`release.yml`](.github/workflows/release.yml) publie sur PyPI à chaque
étiquette `vX.Y.Z`, par **publication de confiance** : aucun jeton à stocker. À faire une
seule fois :

1. Sur PyPI, dans *Your account → Publishing*, ajouter un *pending publisher* GitHub :
   propriétaire `Picsou06`, dépôt `zipguard`, workflow `release.yml`, environnement `pypi`.
   Le projet est créé sur PyPI à la première publication.
2. Côté GitHub, rien à faire : l'environnement `pypi` est créé au premier lancement. On
   peut ensuite y ajouter une règle d'approbation manuelle avant chaque publication.

Ensuite, monter la version dans `pyproject.toml` et `__init__.py`, puis :

```bash
git tag v2.2.0 && git push origin v2.2.0
```

Le workflow refuse une étiquette qui ne correspond pas à la version du paquet.

## 📋 Journal et sécurité

- [`CHANGELOG.md`](CHANGELOG.md) — ce qui a changé, et pourquoi.
- [`SECURITY.md`](SECURITY.md) — comment signaler une faille, et surtout **ce que ZipGuard
  ne promet pas** : archives chiffrées, limite du format 7z, coût de lecture d'un `tar`.

## ⚖️ Éthique

Ce projet est **défensif et pédagogique**. Il explique un mécanisme d'attaque uniquement
pour apprendre à le détecter et à le neutraliser. Aucune charge offensive n'est fournie :
le générateur de démonstration est plafonné à 100 Mo, non imbriqué, et se décompresse
exactement à la taille annoncée. À utiliser sur tes propres systèmes et dans un cadre
d'apprentissage.

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:91EAE4,50:86A8E7,100:7F7FD5&height=140&section=footer&text=Mesurer%20avant%20de%20d%C3%A9compresser&fontSize=22&fontColor=ffffff&fontAlignY=70" width="100%" alt="footer" />

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=15&duration=3000&pause=800&color=7F7FD5&center=true&vCenter=true&width=600&lines=MIT+%C2%A9+2026+%E2%80%94+%40Picsou06+%26+%40CodeByHaamza;Fait+avec+%F0%9F%9B%A1%EF%B8%8F+et+beaucoup+de+curiosit%C3%A9" alt="footer-typing" />

</div>
