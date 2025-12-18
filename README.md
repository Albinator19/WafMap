# WAFMap v1.0 - WAF Offensive Security Tool

**WAFMap** est un outil de pentest automatisé conçu pour la reconnaissance, la détection de Web Application Firewalls (WAF) et le test de techniques d'évasion (*bypass*).

Ce projet a été développé dans le cadre d'un **projet de stage** en cybersécurité. Son objectif principal est d'automatiser l'évaluation de la robustesse des protections périmétriques face à des attaques sophistiquées et obfusquées.

---

## Fonctionnalités principales

* **Reconnaissance & Énumération** : Scan de ports, découverte de sous-domaines et identification d'endpoints d'API.
* **Identification de WAF** : Analyse des en-têtes et des réponses pour identifier les solutions de sécurité (Cloudflare, Akamai, AWS WAF, ModSecurity, etc.).
* **Moteur d'Injection Multi-Vecteurs** :
    * **SQL Injection (SQLi)** : Détection Error-based et Time-based.
    * **Command Injection (CMDi)** : Exploitation de vulnérabilités système avec évasion avancée.
    * **Cross-Site Scripting (XSS)** : Tests de réflexion avec différents niveaux d'encodage.
    * **SSRF** : Contournement de filtres d'IP locales (localhost, 127.0.0.1).
    * **Vecteurs additionnels** : SSTI, LFI, NoSQLi, IDOR, CSRF.
* **Module de Tampering Dynamique** : Application de techniques d'obfuscation (double encodage, changement de casse, commentaires injectés, wildcards Bash) pour tromper les moteurs de détection.
* **Reporting** : Export des résultats en formats TXT, JSON ou HTML pour faciliter l'analyse post-audit.

---

## Architecture Technique

L'outil est architecturé autour d'un moteur central écrit en **Python 3**, privilégiant la modularité :
* **`Engine`** : Orchestrateur gérant les sessions HTTP via `requests.Session` (support des cookies et des proxys).
* **`Tampering`** : Module spécialisé dans la transformation des payloads pour l'évasion.
* **`Multi-threading`** : Utilisation de `ThreadPoolExecutor` pour des scans rapides et efficaces.
* **`urllib.parse`** : Manipulation précise des composants d'URL pour des injections ciblées.

---

## Utilisation

### Installation
```bash
git clone https://github.com/Albinator19/WafMap/
cd wafmap
pip install -r requirements.txt
```
### Exemples de commandes

#### Détection de WAF uniquement :
```bash
python3 wafmap.py --target "http://example.com" --waf-only
```
#### Crawl et découverte d'API :
```bash
python3 wafmap.py --target "http://example.com" --api --crawl
```
#### Audit de vulnérabilité avec Bypass actif (ex: CMDi) :
```bash
python3 wafmap.py --target "http://target.com/api?cmd=127.0.0.1" \
--category cmdi \
--level 3 \
--waf-bypass \
--verbose
```
---

## Note sur le Projet (Stage)

> **WAFMap** est le fruit d'un travail de recherche et de développement réalisé en milieu professionnel. En tant que projet de stage, il est important de prendre en compte les points suivants :

* **État du projet** : Il s'agit d'une version **v1.0 (MVP - Produit Minimum Viable)**. L'outil est pleinement fonctionnel, mais peut présenter des comportements inattendus selon la configuration spécifique des cibles ou des environnements réseau.
* **Améliorations à venir** :
    * **Précision** : Réduction des faux positifs.
    * **Protocole** : Optimisation et stabilisation du module expérimental dédié au **HTTP Request Smuggling**.
    * **Discrétion** : Amélioration de la gestion du *Rate Limiting* pour contourner les bannissements d'IP automatiques.
    * **Expérience Utilisateur** : Développement d'une interface graphique (GUI) pour rendre l'outil plus accessible.

---

## Avertissement Légal

> [!CAUTION]
> **L'utilisation de cet outil est strictement réservée à des tests de sécurité autorisés dans un cadre légal et éthique.**

L'auteur décline toute responsabilité en cas d'utilisation malveillante, de dommages causés à des systèmes tiers ou d'activités illégales. Pour rappel, l'accès ou le maintien frauduleux dans un système de traitement automatisé de données est puni par la loi. **Hacking is illegal.**

---
