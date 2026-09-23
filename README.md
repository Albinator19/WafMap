# WAFMap v1.2 - WAF Offensive Security Tool

**WAFMap** est un outil de pentest automatisé conçu pour la reconnaissance, la détection de Web Application Firewalls (WAF) et le test de techniques d'évasion (*bypass*).

Son objectif principal est d'automatiser l'évaluation de la robustesse des protections périmétriques face à des attaques sophistiquées et obfusquées.

---

## Fonctionnalités principales

* **Reconnaissance & Énumération** : Scan de ports, découverte de sous-domaines et identification d'endpoints d'API, avec contrôle de périmètre (`--allowed-domains`).
* **Identification de WAF** : Analyse des en-têtes et des réponses pour identifier les solutions de sécurité (Cloudflare, Akamai, AWS WAF, ModSecurity, etc.), avec des signatures propres à chaque solution pour éviter les faux positifs croisés.
* **Authentification** : Flow de login automatique avant le scan (`--login-url`), pour auditer des zones authentifiées.
* **Moteur d'Injection Multi-Vecteurs** :
    * **SQL Injection (SQLi)** : Détection Error-based, In-Band, Boolean-Blind (avec contrôle de stabilité de page) et Time-Based (avec confirmation en double).
    * **Command Injection (CMDi)** : Exploitation de vulnérabilités système avec évasion avancée et confirmation en double pour le time-based.
    * **Cross-Site Scripting (XSS)** : Tests de réflexion avec différents niveaux d'encodage et exclusion du contexte "commentaire HTML".
    * **SSRF** : Contournement de filtres d'IP locales (localhost, 127.0.0.1).
    * **IDOR** : Test différentiel à deux comptes (`--second-session-cookie`) quand disponible, sinon heuristique marquée "à vérifier".
    * **CSRF** : Prend en compte la protection `SameSite` des cookies de session avant de conclure.
    * **Vecteurs additionnels** : SSTI, LFI, NoSQLi.
* **Module de Tampering Dynamique avec Oracle de Bypass** : Avant chaque catégorie de test (SQLi, XSS, LFI, CMDi, SSRF, SSTI, NoSQLi), un payload canari est envoyé pour vérifier s'il est bloqué ; si oui, chaque technique d'évasion disponible est testée de façon déterministe jusqu'à en trouver une qui passe. La technique gagnante est réutilisée pour tout le scan sur ce point d'entrée et **rapportée comme un finding à part entière** ("telle technique contourne tel WAF").
* **Limitation de débit globale** : Plafond de requêtes/seconde partagé par tous les threads (`--rate-limit`), pour limiter le risque de ban IP automatique.
* **Reporting** : Export des résultats en formats TXT, JSON ou HTML, avec séparation claire entre vulnérabilités **confirmées**, **à vérifier manuellement** et **findings de reconnaissance** (CVE publiques, endpoints API).

---

## Architecture Technique

L'outil est architecturé autour d'un moteur central écrit en **Python 3**, privilégiant la modularité :
* **`Engine`** : Orchestrateur gérant les sessions HTTP via `requests.Session` (support des cookies, du proxy, d'une seconde session pour l'IDOR, et d'une liste de cibles via `--target-list`).
* **`Auth`** : Module de login automatique avant le lancement du scan.
* **`RateLimiter`** : Limiteur de débit global thread-safe partagé par tous les workers.
* **`Tampering`** : Module spécialisé dans la transformation des payloads pour l'évasion, 4 à 6 techniques distinctes et sélectionnables explicitement par catégorie.
* **`BypassOracle`** : Envoie un payload canari, détecte le blocage (code HTTP ou signature WAF), teste chaque technique jusqu'à en trouver une qui fonctionne, et met le résultat en cache par (catégorie, URL).
* **`Multi-threading`** : Utilisation de `ThreadPoolExecutor` pour des scans rapides et efficaces.
* **`urllib.parse`** : Manipulation précise des composants d'URL pour des injections ciblées.

---

## Utilisation

### Installation
```bash
git clone https://github.com/Albinator19/WafMap/
cd WafMap
pip install -r requirements.txt
```
### Exemples de commandes

#### Détection de WAF uniquement :
```bash
python3 wafmap.py --target "http://example.com" --waf-only
```
#### Crawl et découverte d'API :
```bash
python3 wafmap.py --target "http://example.com" --api-scan --crawl
```
#### Audit de vulnérabilité avec Bypass actif (ex: CMDi) :
```bash
python3 wafmap.py --target "http://target.com/api?cmd=127.0.0.1" \
--category cmdi \
--level 3 \
--waf-bypass \
--verbose
```
#### Scan authentifié, plusieurs cibles, débit maîtrisé :
```bash
python3 wafmap.py --target-list targets.txt \
--login-url "http://target.com/login" \
--login-data "user=test&pass=test" \
--allowed-domains "target.com" \
--rate-limit 5 \
--category all
```
#### Test IDOR différentiel à deux comptes :
```bash
python3 wafmap.py --target "http://target.com/profile?id=1" \
--category idor \
--second-session-cookie "session=COOKIE_DU_COMPTE_B"
```

---

## Différences par rapport à la v1.1

Cette version corrige des problèmes touchant spécifiquement la fonctionnalité de **bypass de WAF** (`--waf-bypass`), qui était non-opérationnelle en v1.1 malgré sa présence dans le code.

* **Correction critique (bypass totalement inopérant)** : `tampering.py` encodait manuellement les payloads (ex: espaces en `%09`), mais ce payload déjà encodé était ensuite passé à `requests` via un dictionnaire (`params=`/`data=`), qui l'encodait **une seconde fois**. Le serveur recevait la chaîne littérale `%2527%252F...` au lieu d'un payload exploitable vérifié byte pour byte avant correction. Corrigé par un nouvel envoi "brut" (`Engine._send_request_raw`) qui construit l'URL/le corps déjà encodés sans repasser par le dictionnaire `requests`, appliqué à tous les vecteurs (SQLi, XSS, LFI, CMDi, SSRF, SSTI, NoSQLi).
* **Correction d'un bug de sémantique SQL** : `sql_obfuscate` remplaçait systématiquement `OR`→`||` et `AND`→`&&`, une syntaxe propre à MySQL. Sur SQLite, PostgreSQL, MSSQL ou Oracle, `||` est un opérateur de concaténation (pas OR) et `&&` n'existe pas : cette conversion cassait silencieusement l'injection sur la majorité des SGBD. Supprimée.
* **Ajout d'un oracle de vérification (`bypass_oracle.py`)** : auparavant, une technique d'évasion était choisie au hasard à chaque requête, sans jamais vérifier si elle avait réellement traversé le WAF. Désormais, un payload canari est envoyé pour chaque catégorie active ; s'il est bloqué (code HTTP ou signature WAF détectée), chaque technique disponible est testée **une par une, de façon déterministe**, jusqu'à en trouver une qui fonctionne. La technique gagnante est mise en cache par (catégorie, URL) et réutilisée pour le reste du scan, garantissant reproductibilité et rapidité.
* **Un vrai livrable de pentest** : chaque test de bypass (réussi ou non) est enregistré comme un finding séparé et apparaît dans une nouvelle section "Techniques de bypass WAF" du rapport (TXT/JSON/HTML) — exactement l'information qu'un pentester met dans un rapport de mission ("Cloudflare est contourné sur ce paramètre via la technique X"), plutôt qu'une liste de payloads obfusqués sans verdict.
* **Techniques rendues explicitement sélectionnables** pour les 7 catégories (`SQLI_TECHNIQUES`, `XSS_TECHNIQUES`, `LFI_TECHNIQUES`, `CMDI_TECHNIQUES`, `SSRF_TECHNIQUES`, `SSTI_TECHNIQUES`, `NOSQLI_TECHNIQUES`), au lieu d'un tirage aléatoire interne non contrôlable, nécessaire pour que l'oracle puisse tester chaque technique isolément et de façon reproductible.
* **Portée** : l'oracle couvre désormais l'intégralité des 7 vecteurs (SQLi, XSS, LFI, CMDi, SSRF, SSTI, NoSQLi), validés soit en conditions réelles contre une cible locale volontairement vulnérable (SQLi, CMDi), soit par test de contrôle de flux avec moteur simulé pour les vecteurs sans endpoint de démonstration disponible (LFI, SSRF, SSTI, NoSQLi).

### Correctif (suite à un test contre une cible réelle derrière Cloudflare)

* **Faux positifs de blocage systématiques derrière un WAF passif (ex: Cloudflare)** : `bypass_oracle._is_blocked()` utilisait `match_signatures()` avec détection par en-tête/cookie incluse, or un en-tête comme `cf-ray` est présent sur *toutes* les réponses Cloudflare, qu'elles soient bloquées ou non. L'oracle concluait donc systématiquement à un blocage et testait toutes les techniques pour rien, même quand le WAF ne bloquait strictement rien (des centaines de requêtes inutiles par catégorie sur une cible réelle). Corrigé : seul un code HTTP de blocage (400/403/406/500/501) ou une signature de **page de blocage** explicite dans le corps de la réponse déclenche désormais l'oracle, la simple présence d'un WAF n'est plus confondue avec un blocage actif.
* **Court-circuit basé sur le statut réel du WAF** : le statut déterminé par `detect_waf()` (Actif/Bloquant vs Passif/Non-Bloquant) est maintenant réutilisé par l'oracle (`engine.waf_is_blocking`) pour éviter de lancer la moindre requête de test de bypass sur une cible dont le WAF est déjà connu comme non-bloquant.

---

## Avertissement Légal

> [!CAUTION]
> **L'utilisation de cet outil est strictement réservée à des tests de sécurité autorisés dans un cadre légal et éthique.**

L'auteur décline toute responsabilité en cas d'utilisation malveillante, de dommages causés à des systèmes tiers ou d'activités illégales.

---
