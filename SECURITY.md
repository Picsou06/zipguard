# Politique de sécurité

ZipGuard est un outil **défensif et pédagogique**. Il explique un mécanisme d'attaque pour
apprendre à le détecter et à le neutraliser, et n'embarque aucune charge offensive.

## Signaler une faille

Si tu trouves une archive que ZipGuard juge sûre alors qu'elle ne l'est pas, ou une entrée
qui réussit à écrire hors du dossier cible, c'est une faille et elle nous intéresse.

Ouvre une [issue](https://github.com/Picsou06/zipguard/issues) **sans joindre l'archive**.
Décris plutôt comment la reconstruire : format, nombre d'entrées, structure, et ce que les
métadonnées annoncent par rapport à ce que le fichier contient réellement. Le dépôt ne doit
héberger aucune bombe prête à l'emploi, pas même en pièce jointe d'un rapport.

Pour une faille que tu préfères ne pas rendre publique tout de suite, passe par les
[avis de sécurité privés](https://github.com/Picsou06/zipguard/security/advisories/new)
de GitHub.

## Ce que ZipGuard promet

- Rendre un **verdict** sur toute entrée, même hostile ou corrompue, jamais une trace
  d'exception.
- Ne jamais écrire hors du dossier de destination demandé.
- Ne jamais écrire plus d'octets que les quotas configurés, même si le manifeste ment.
- Effacer ce qui a été écrit quand une extraction est interrompue.

## Ce que ZipGuard ne promet pas

Ces limites sont connues et documentées dans
[docs/03-anatomie.md](docs/03-anatomie.md) :

- **Les archives chiffrées** ne sont pas inspectables, et ZipGuard ne prétend pas le
  contraire.
- **Le format 7z** passe par un dossier temporaire pour lire une entrée, parce que `py7zr`
  ne sait pas rendre un flux borné. Un manifeste menteur y est détecté une fois l'entrée
  écrite, pas avant.
- **Lister un `tar` compressé impose de traverser tout le flux.** Le plafond de lecture
  borne ce coût, il ne le supprime pas.
- **Le worker du mode service est tué sur un délai**, ce qui borne le temps mais pas la
  mémoire. Un bac à sable système (seccomp, cgroups) serait le cran au dessus.

## Utilisation responsable

Le générateur de démonstration est plafonné à 100 Mo, ne produit qu'une seule entrée, non
imbriquée, et se décompresse exactement à la taille annoncée. Il illustre le ratio de
compression sans pouvoir servir d'arme. À utiliser sur tes propres systèmes et dans un
cadre d'apprentissage.
