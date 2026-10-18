# Se protéger des bombes de décompression

La règle d'or : **ne jamais faire confiance aux métadonnées, toujours mesurer en lisant.**

## Les huit garde fous

Les six premiers décident du **verdict**, à partir de ce que l'archive raconte et de ce
qu'on mesure en la lisant. Les deux derniers protègent le **disque** pendant l'écriture,
une fois le verdict rendu, parce qu'un verdict favorable n'est pas un blanc seing.

1. **Plafond de taille décompressée totale.** Additionner les tailles annoncées et refuser
   au delà d'un seuil. ZipGuard : `max_total_bytes`.
2. **Plafond par entrée.** Un seul membre ne doit pas pouvoir dépasser une limite.
   ZipGuard : `max_entry_bytes`.
3. **Ratio de compression maximal.** Taille décompressée divisée par taille compressée.
   Un ratio de 1000x est presque toujours une attaque. ZipGuard : `max_ratio`.
4. **Nombre d'entrées maximal.** Des millions de fichiers vides épuisent aussi les
   ressources. ZipGuard : `max_entries`.
5. **Profondeur d'imbrication maximale.** ZipGuard descend réellement dans les archives
   filles jusqu'à `max_depth` et rend l'arbre complet des verdicts.
6. **Budget d'inspection des imbriquées.** Borne le nombre total d'archives filles
   ouvertes. ZipGuard : `max_nested_scans`.
7. **Quota d'octets réellement écrits.** Recompter pendant l'écriture, pas seulement avant.
   ZipGuard : `max_extract_bytes`.
8. **Marge d'espace libre exigée.** Refuser de commencer, et s'arrêter en cours, si le
   disque descend sous un plancher. ZipGuard : `min_free_bytes`.

## Pourquoi mesurer pendant la lecture

Les champs de taille d'un ZIP sont déclaratifs : rien n'oblige une archive malveillante à
dire la vérité. Un attaquant peut annoncer une petite taille et fournir un flux qui ne
s'arrête jamais. La seule défense fiable est de **compter les octets réellement produits**
et de s'arrêter net au dépassement, bloc par bloc.

Certains formats rendent cette règle obligatoire dès l'inventaire :

| Format | Ce qu'il déclare | Ce que ZipGuard fait |
| :-- | :-- | :-- |
| `zip`, `7z` | Un manifeste complet | Le lit, puis le vérifie pendant l'écriture |
| `tar`, `tar.*` | Aucune taille compressée par entrée | Mesure en traversant le flux une fois |
| `gz`, `bz2`, `xz` | Une taille *modulo 4 Gio* pour gzip | Ignore la déclaration et compte lui même |

Pour les formats de la deuxième et de la troisième ligne, lister les entrées impose de
décompresser. ZipGuard le fait derrière un compteur qui coupe au seuil, ce qui transforme
**l'inventaire lui même en garde fou** : l'archive est refusée en cours de lecture, sans
jamais avoir été entièrement déballée.

Cela se voit dans le banc d'essai : le cas `lecture-coupee.tar.gz` annonce 3,8 Mio et le
refus tombe après 490 Kio lus.

## Reconnaître le format, pas l'extension

Une archive renommée en `notes.txt` reste une archive. ZipGuard reconnaît chaque fichier
par sa **signature** (les premiers octets), jamais par son nom. C'est ce qui permet de
repérer une bombe imbriquée que son auteur a pris soin de déguiser.

## La bombe cachée un niveau plus bas

Une archive externe peut afficher un ratio parfaitement innocent tout en contenant une
bombe. Le manifeste externe ne voit qu'un fichier déjà compressé, donc incompressible :
ratio 1.0x, verdict rassurant. C'est le cas que tout scanner non récursif laisse passer.

La règle qui en découle : **quand on ne peut pas descendre, on refuse**. Si `max_depth`
interdit d'ouvrir une archive fille, son contenu est déclaré invérifiable, et invérifiable
vaut refus. Un défenseur ne fait pas confiance à ce qu'il n'a pas pu lire.

## Le dernier mot revient à l'écriture

Un verdict favorable n'est pas un blanc seing. Le manifeste a pu mentir, donc l'extraction
recompte chaque octet écrit face à `max_extract_bytes`, surveille l'espace libre, et en cas
de dépassement **annule toute l'extraction** avant de remonter l'erreur.

Annuler proprement suppose de ne rien avoir écrit dans la destination. Effacer après coup
ne suffit pas : si l'archive contient un `a.txt` et que la destination en avait déjà un,
l'effacement emporte le fichier de l'utilisateur avec. ZipGuard écrit donc tout dans un
dossier de préparation, placé dans la destination pour rester sur le même disque, et ne
déplace l'arborescence qu'une fois la dernière entrée passée. Une extraction refusée ne
laisse rien derrière elle, et ne retire rien non plus.

Le verdict lui même doit porter sur ce qui sera extrait. Inspecter un fichier puis le
rouvrir pour l'extraire laisse une fenêtre où il peut être remplacé. L'archive est donc
recopiée dans un dossier privé, et c'est cette copie, et elle seule, qui est inspectée puis
extraite.

## Zip Slip et liens symboliques

Un décompresseur doit refuser les noms d'entrée qui sortent du dossier cible. ZipGuard
traite les trois pièges classiques avant d'écrire quoi que ce soit :

- le chemin absolu (`/etc/passwd`), que `tar` conserve tel quel ;
- la lettre de lecteur Windows (`C:\Windows\...`) ;
- la remontée par deux points (`../../etc/passwd`).

Le chemin résolu est ensuite vérifié une seconde fois, pour attraper ce que les règles
auraient laissé passer.

Les **liens symboliques** sont refusés par défaut, dans `tar`, dans `7z`, comme dans
`zip`, où ils se cachent dans les bits de mode des attributs externes. Un lien pointant
hors de l'arborescence permet de rediriger une écriture vers n'importe quel fichier du
système : c'est une évasion du même genre que le Zip Slip, sous un autre déguisement.

Avec `--allow-links`, un lien est recréé seulement si sa cible **ne fait que descendre** :
relative, sans `..`, sans lettre de lecteur. La règle est plus stricte que « reste dans le
dossier », et c'est voulu : vérifier qu'une cible reste dedans oblige à suivre les autres
liens de l'archive, alors qu'une cible qui ne remonte jamais ne peut pas sortir, quelle
que soit la chaîne de liens. Aucune entrée ne peut non plus passer *à travers* un lien de
l'archive, et les liens physiques sont toujours refusés.

Deux autres pièges sont arrêtés au même endroit :

- **les entrées en double** : si deux entrées portent le même nom, la seconde écrase la
  première, et ce qui arrive sur le disque n'est plus ce que l'inspection a vu ;
- **les conflits de forme** : un nom qui sert à la fois de fichier et de dossier, ou un
  fichier qui prendrait la place d'un dossier déjà présent dans la destination.

Tous ces contrôles ont lieu **pendant une passe de validation préalable**, donc avant la
première écriture : une archive piégée ne laisse aucune trace sur le disque.

## En production

- Décompresser dans un bac à sable isolé (conteneur en lecture seule, quota disque).
- Journaliser chaque refus avec sa raison : la sortie `--json` est faite pour ça.
- Traiter les archives dans un worker séparé que l'on peut tuer sans affecter le service.
  C'est exactement ce que fait `zipguard serve`, qui plafonne le dégât d'une archive
  pathologique à un processus perdu et transforme un délai dépassé en réponse `504`.
- Plafonner la mémoire du worker, pas seulement son temps : un délai ne protège pas d'une
  allocation géante. `zipguard serve` pose un `RLIMIT_AS` (`--max-memory-mb`) et rend un
  verdict DANGEREUSE quand il est atteint.
- Protéger le service lui même : un délai sur chaque lecture réseau contre les envois au
  compte goutte, et un nombre borné d'analyses simultanées (`--read-timeout`,
  `--max-concurrent`).
