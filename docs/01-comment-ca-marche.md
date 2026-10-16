# Comment fonctionne une bombe de décompression

> Objectif pédagogique : comprendre le mécanisme pour mieux s'en protéger. Ce dépôt
> ne fournit aucune bombe prête à l'emploi.

## Le principe

Une **bombe de décompression** (ou *zip bomb*) est une archive volontairement minuscule
qui, une fois décompressée, produit une quantité de données énorme, suffisante pour
saturer la mémoire vive ou le disque de la machine qui l'ouvre. C'est une attaque par
**déni de service** : elle ne vole rien, elle épuise une ressource.

Tout repose sur le **ratio de compression**. Les algorithmes sans perte comme DEFLATE
remplacent les répétitions par de courtes références. Un fichier d'un gigaoctet composé
du même octet répété se compresse en quelques kilooctets, car l'algorithme n'a qu'à
encoder « cet octet, un milliard de fois ».

## Les trois familles

| Famille | Idée | Détection |
| --- | --- | --- |
| Fichier unique très répétitif | Un seul membre énorme et ultra redondant | Ratio de compression anormal |
| Archive imbriquée | Des archives dans des archives, sur plusieurs niveaux | Profondeur et présence de `.zip` internes |
| Recouvrement d'entrées | Plusieurs entrées pointant vers les mêmes données compressées | Somme des tailles annoncées contre taille réelle |

## Pourquoi c'est dangereux

Un décompresseur naïf lit l'en-tête, voit un petit fichier, et commence à écrire la
sortie sans jamais vérifier combien d'octets il a déjà produits. La mémoire ou le disque
se remplit avant qu'il ne s'arrête. Le service tombe.

La bonne nouvelle : toutes ces familles partagent une signature mesurable **avant**
d'écrire quoi que ce soit. C'est exactement ce que lit le scanner de ce dépôt. Voir
[02-prevention.md](02-prevention.md).
