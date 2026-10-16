# Anatomie du dépôt

```
zipguard/
├── README.md                 présentation animée et guide de prise en main
├── compose.dev.yaml          orchestration de développement
├── compose.prod.yaml         orchestration de production durcie
├── docs/                     cours et explications
│   ├── 01-comment-ca-marche.md
│   ├── 02-prevention.md
│   └── 03-anatomie.md
├── samples/                  archives de démonstration générées localement
└── zipguard.app/             service applicatif (code + Docker)
    ├── Dockerfile
    ├── pyproject.toml
    ├── src/zipguard/
    │   ├── limits.py         seuils de sécurité immuables
    │   ├── scanner.py        inspection et extraction plafonnée
    │   ├── demo.py           générateur de démonstration borné
    │   ├── report.py         rendu lisible d'un verdict
    │   └── __main__.py       interface en ligne de commande
    └── tests/                couverture du comportement
```

## Le flux d'une inspection

1. `__main__.scan` lit les arguments et construit un objet `Limits`.
2. `Scanner.inspect` ouvre l'archive, lit les métadonnées, calcule les statistiques.
3. Chaque seuil dépassé ajoute une raison ; un `Verdict` est rendu.
4. `report.render` transforme le verdict en rapport lisible.
5. Le code de sortie vaut `0` si l'archive est sûre, `1` sinon : utilisable dans un script.

## La frontière de sécurité

Le module `demo.py` plafonne la taille à 100 Mo et ne produit qu'une seule entrée, non
imbriquée, qui se décompresse exactement à la taille annoncée. Il illustre le ratio de
compression sans jamais pouvoir servir d'arme. Toute la logique offensive est donc
absente du dépôt : il n'y a que de la mesure et de la défense.
