# Autorisations API

Le moteur applique une politique fournie dans un manifeste, sur des endpoints connus. Il ne découvre pas toutes les règles métier. Les scénarios sont limités à GET, sans redirection, et au préfixe déclaré. Les réponses sont limitées à 1 Mio. Les identifiants exigent HTTPS, sauf sur le laboratoire local.

## Démonstration Windows

Dans le dossier ProbeKit, démarrer le laboratoire dans un terminal :

```powershell
python examples/lab.py
```

Dans un deuxième terminal, après `python -m pip install -e .` :

```powershell
$env:PROBEKIT_ALICE='Bearer lab-alice'
$env:PROBEKIT_BOB='Bearer lab-bob'
probekit-auth examples/authorization.json --output reports/demo
```

Sans installation, définir `$env:PYTHONPATH='src'` puis remplacer `probekit-auth` par `python -m probekit.authorization`. La démonstration détecte une violation ; le code de sortie 1 indique des constats ou erreurs. Le rapport doit contenir une violation sur l'endpoint vulnérable et un résultat `passed` sur l'endpoint corrigé.

Pour le tableau de bord, définir les mêmes variables **avant** de lancer `probekit-ui`, puis coller le manifeste dans le formulaire des autorisations API. Les rapports JSON et HTML contiennent la matrice des résultats.

## Interprétation

- `violation` : un compte déclaré interdit reçoit la ressource identifiée par tous les marqueurs, avec une référence autorisée vérifiée.
- `passed` : tous les comptes testés respectent la politique déclarée sur ce scénario uniquement.
- `inconclusive` : identité invalide, référence absente, réponse ambiguë ou collecte impossible.

Les identités attendues doivent désigner des utilisateurs réellement distincts. Choisir des marqueurs spécifiques de la ressource protégée, pas un simple champ `success`. La qualité des conclusions dépend de la politique fournie. Un résultat peut révéler une politique déclarée incorrecte : les constats nécessitent une revue.

Les rapports gardent statuts, noms des comptes, SHA-256 et concordance des marqueurs. Ils ne gardent ni jetons, ni corps des réponses, ni valeurs attendues des marqueurs. Ne pas placer de secrets dans les URL ou noms de scénarios. Éviter les valeurs sensibles dans le manifeste lui-même.

## Comparateur C++

La similarité des JSON canoniques est un indice complémentaire. Elle utilise un Jaccard multiensemble de trigrammes d'octets ; elle ne confirme jamais une violation seule. Les champs dynamiques peuvent diminuer ce score.

```sh
cmake -S native -B build/native -DCMAKE_BUILD_TYPE=Release
cmake --build build/native --config Release
```

Placer `probekit_compare.dll` (Windows) ou `probekit_compare.so` (Linux) dans `src/probekit/_native`, ou définir `PROBEKIT_NATIVE_PATH`. Le calcul Python équivalent fonctionne sans cette bibliothèque. La DLL incluse est compilée pour Windows x64. Aucun gain de performance n'est revendiqué sans benchmark adapté.

## Avant commercialisation

Cette version ne gère pas OAuth, renouvellement des jetons, tests POST/PUT/DELETE, GraphQL, découverte OpenAPI, annulation des audits, chiffrement de l'historique ou licences. Le tableau de bord est local et mono-utilisateur. Un GET peut avoir des effets de bord dans une API mal conçue : sélectionner des endpoints de lecture. Valider une couverture plus large, les faux positifs et la reproductibilité avant de vendre le produit comme outil complet.
