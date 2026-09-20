# WAFMap v1.1 - WAF Offensive Security Tool

**WAFMap** est un outil de pentest automatisé conçu pour la reconnaissance, la détection de Web Application Firewalls (WAF) et le test de techniques d'évasion (*bypass*).

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
* **Module de Tampering Dynamique** : Application de techniques d'obfuscation (double encodage, changement de casse, commentaires injectés, wildcards Bash) pour tromper les moteurs de détection.
* **Limitation de débit globale** : Plafond de requêtes/seconde partagé par tous les threads (`--rate-limit`), pour limiter le risque de ban IP automatique.
* **Reporting** : Export des résultats en formats TXT, JSON ou HTML, avec séparation claire entre vulnérabilités **confirmées**, **à vérifier manuellement** et **findings de reconnaissance** (CVE publiques, endpoints API).

---

## Architecture Technique

L'outil est architecturé autour d'un moteur central écrit en **Python 3**, privilégiant la modularité :
* **`Engine`** : Orchestrateur gérant les sessions HTTP via `requests.Session` (support des cookies, du proxy, d'une seconde session pour l'IDOR, et d'une liste de cibles via `--target-list`).
* **`Auth`** : Module de login automatique avant le lancement du scan.
* **`RateLimiter`** : Limiteur de débit global thread-safe partagé par tous les workers.
* **`Tampering`** : Module spécialisé dans la transformation des payloads pour l'évasion.
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

## Différences par rapport à la v1.0

Cette version corrige plusieurs problèmes de fiabilité identifiés lors d'un audit de code complet du MVP, et ajoute les fonctionnalités jugées prioritaires pour un usage en mission réelle.

* **Réduction des faux positifs** :
    * `idor.py` : ne conclut plus à une IDOR sur un simple code 200 ; teste désormais un identifiant clairement invalide en référence, et effectue un vrai test différentiel à deux comptes si `--second-session-cookie` est fourni.
    * `csrf.py` : vérifie l'attribut `SameSite` des cookies de session avant de signaler une absence de protection CSRF.
    * `detection.py` : suppression des signatures de body génériques ("403 forbidden", "406 not acceptable") partagées entre plusieurs WAF, qui provoquaient des détections multiples et contradictoires sur une simple page d'erreur générique.
    * `sqli.py` : ajout d'un contrôle de stabilité de page avant le test boolean-blind (une page au contenu naturellement variable désactive ce test pour éviter les faux positifs) ; le time-based exige désormais une confirmation par une deuxième requête plutôt qu'une seule mesure.
* **Fiabilité du code** :
    * Suppression de tous les `except:` nus : les erreurs sont maintenant visibles en mode `--verbose` au lieu d'être avalées silencieusement.
    * Arrêt des tests sur un vecteur (URL + paramètre) dès qu'une vulnérabilité y est confirmée, pour réduire le bruit du rapport et le temps de scan (`sqli.py`, `xss.py`, `cmdi.py`).
    * Ajout d'un `.gitignore` (le dossier `__pycache__` était committé).
* **Nouvelles fonctionnalités pour un usage professionnel** :
    * Flow d'authentification avant scan (`--login-url`, `--login-data`, `--login-success-text`).
    * Scan de plusieurs cibles en une seule commande (`--target-list`).
    * Contrôle explicite du périmètre pour les sous-domaines et ports découverts (`--allowed-domains`), au lieu d'un scope implicite illimité.
    * Limitation de débit globale et thread-safe (`--rate-limit`), en plus du backoff existant sur 429/503.
* **Reporting** : les rapports (TXT/JSON/HTML) séparent désormais les vulnérabilités **confirmées** des findings **à vérifier manuellement**, et isolent les découvertes de reconnaissance (CVE publiques du WAF détecté, endpoints API) qui ne sont pas des vulnérabilités prouvées sur la cible.
* **Correction de documentation** : l'exemple `--api` du README (v1.0) ne correspondait à aucune option réelle du CLI ; corrigé en `--api-scan`.

---

## Avertissement Légal

> [!CAUTION]
> **L'utilisation de cet outil est strictement réservée à des tests de sécurité autorisés dans un cadre légal et éthique.**

L'auteur décline toute responsabilité en cas d'utilisation malveillante, de dommages causés à des systèmes tiers ou d'activités illégales.

---
