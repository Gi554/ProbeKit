# ProbeKit

Prototype d'un produit d'audit web/API en Python 3.11+, avec comparateur C++ optionnel. À utiliser dans un environnement dont le test est autorisé.

## Autorisations API

Le module multi-comptes vérifie des scénarios de permissions explicites : identité de chaque compte, référence autorisée, accès interdits et marqueurs de ressource. Un laboratoire vulnérable et corrigé est inclus. Voir [le guide et les commandes de démonstration](docs/AUTHORIZATION.md). Le tableau de bord permet aussi de soumettre les manifestes JSON.

## Tableau de bord

Sur Windows, lancer `./Start-ProbeKit.ps1` depuis PowerShell avec Python 3.11+ installé, ou passer `-PythonPath` vers votre exécutable Python. Le script utilise les sources directement.

```sh
python -m pip install -e .
probekit-ui --port 8765 --data data/probekit.sqlite
```

Ouvrir http://127.0.0.1:8765. Créer un audit avec un nom de projet et une URL. L'interface affiche les travaux en attente, les résultats, leurs preuves et les rapports téléchargeables. Deux audits peuvent tourner en parallèle, avec une limite de vingt travaux en attente ou en cours. L'historique utilise SQLite ; sa vue est limitée aux cent audits les plus récents.

Sans installation : définir PYTHONPATH=src, puis `python -m probekit.server`. Le serveur écoute exclusivement sur l'interface locale. Il n'a pas de comptes utilisateurs ni de gestion de clients ; cette version ne doit pas être utilisée comme serveur SaaS public. Les pages sont générées en Python, avec HTML/CSS et sans JavaScript.

## Première version

Un contrôle de configuration collecte les en-têtes d'une réponse HTTP, les attributs des cookies (sans conserver leur valeur), la version TLS négociée et la validité du certificat. Les résultats sont exportés en JSON et HTML. Une redirection ne peut pas changer d'origine : protocole, hôte et port restent identiques.

L'audit de configuration ne réalise pas d'exploitation, de recherche de mots de passe ou de découverte de chemins. Le module d'autorisations utilise des identifiants de test fournis par variables d'environnement. Les en-têtes manquants sont des constats à examiner, pas des preuves suffisantes de vulnérabilité. Les besoins d'API et de pages HTML sont distingués pour les contrôles CSP et d'encadrement.

```sh
python -m venv .venv
python -m pip install -e .
probekit http://127.0.0.1:8000 --output reports/local
```

Sans installation, définir PYTHONPATH=src puis utiliser `python -m probekit URL`.

Les contrôles TLS utilisent le magasin de confiance de Python. Les réponses HTTP d'erreur sont analysées, mais une erreur de collecte reste signalée. Le délai s'applique aux opérations réseau individuelles ; ce n'est pas une limite globale de durée. Le corps de la réponse n'est pas enregistré.

## Architecture

- `target.py` : validation d'URL et périmètre des redirections.
- `audit.py` : collecte HTTP et TLS.
- `checks.py` : règles de configuration.
- `models.py` : constats et rapport structuré.
- `render.py` : exports, avec échappement HTML.
- `cli.py` : ligne de commande.
- `store.py` : historique SQLite et récupération après interruption.
- `jobs.py` : file de travaux en arrière-plan.
- `server.py` / `dashboard.py` : interface locale et téléchargements des rapports.

Tests : `python -m unittest discover -s tests -v`, avec PYTHONPATH=src. Les tests HTTP utilisent des serveurs temporaires sur 127.0.0.1, dont le laboratoire API vulnérable et corrigé ; ils ne sollicitent aucun site externe. Les tests du comparateur vérifient aussi sa concordance avec le calcul Python sur des données binaires.

## Trajectoire produit

Le positionnement visé est un outil local de vérification des permissions API pour équipes de développement et pentesteurs. La vente et le déploiement public ne sont pas activés par ce prototype.

Avant une version commerciale : validation de la couverture et des faux positifs sur un laboratoire, gestion des périmètres par projet, scans authentifiés, comparaison avant/après correction, comptes et rôles, séparation des données clients, journal des actions, gestion des secrets et politiques de rétention. Une version hébergée aurait aussi besoin d'une politique de sorties réseau et d'une protection SSRF adaptée.

Les recommandations de configuration sont fondées sur les références [OWASP HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) et [Secure Headers Project](https://owasp.org/projects/secure-headers-project). Le périmètre actuel est bien plus limité que le [Web Security Testing Guide](https://owasp.org/projects/web-security-testing-guide).

Les rapports et la base locale contiennent les URL fournies et les erreurs de collecte. Aucun corps de page ni valeur de cookie n'est conservé. Aucun dépôt ou service public n'est créé automatiquement.
