# Se protéger des bombes de décompression

La règle d'or : **ne jamais faire confiance aux métadonnées, toujours mesurer en lisant.**

## Les six garde fous

1. **Plafond de taille décompressée totale.** Additionner les `file_size` annoncés et
   refuser au delà d'un seuil. ZipGuard : `max_total_bytes`.
2. **Plafond par entrée.** Un seul membre ne doit pas pouvoir dépasser une limite.
   ZipGuard : `max_entry_bytes`.
3. **Ratio de compression maximal.** Taille décompressée divisée par taille compressée.
   Un ratio de 1000x est presque toujours une attaque. ZipGuard : `max_ratio`.
4. **Nombre d'entrées maximal.** Des millions de fichiers vides épuisent aussi les
   ressources. ZipGuard : `max_entries`.
5. **Profondeur d'imbrication maximale.** Interdire ou limiter les archives dans les
   archives. ZipGuard : `max_depth`.
6. **Lecture plafonnée pendant l'extraction.** Même après validation, compter les octets
   écrits et couper au dépassement, car l'en-tête peut mentir. ZipGuard : `safe_extract`.

## Pourquoi mesurer pendant la lecture

Les champs de taille d'un ZIP sont déclaratifs : rien n'oblige une archive malveillante à
dire la vérité. Un attaquant peut annoncer une petite taille et fournir un flux qui ne
s'arrête jamais. La seule défense fiable est de **compter les octets réellement produits**
et de s'arrêter net au dépassement, bloc par bloc. C'est le rôle de `_stream_entry`.

## Bonus : le Zip Slip

Au passage, un décompresseur doit refuser les noms d'entrée qui sortent du dossier cible
(par exemple `../../etc/passwd`). ZipGuard résout chaque chemin et vérifie qu'il reste
contenu dans la racine autorisée (`Scanner._resolve`).

## En production

- Décompresser dans un bac à sable isolé (conteneur en lecture seule, quota disque).
- Journaliser chaque refus avec sa raison.
- Traiter les archives dans un worker séparé que l'on peut tuer sans affecter le service.
