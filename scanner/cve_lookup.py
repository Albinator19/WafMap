import requests
import time

def search_cve(waf_name):
    """
    Interroge l'API publique NVD (NIST) pour trouver les vulnérabilités (CVE)
    associées à la technologie WAF détectée.
    """
    # Inutile de chercher si le WAF est inconnu ou générique
    if not waf_name or any(x in waf_name for x in ["Aucun", "Inconnu", "Inaccessible", "Generic"]):
        return []

    # Extraction du nom principal du logiciel
    # Ex: "ModSecurity / Nginx (Heuristic)" devient "ModSecurity"
    search_term = waf_name.split('(')[0].split('/')[0].strip()
    
    if not search_term or len(search_term) < 3:
        return []

    print(f"[*] Recherche de CVEs connues pour : {search_term}...")
    
    # Utilisation de l'API NVD 2.0
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': search_term,
        'resultsPerPage': 3, # Limitation volontaire pour ne garder que les plus pertinentes
        'sortOrder': 'DESC', # Tri par date décroissante
        'pubStartDate': '2020-01-01T00:00:00.000' # On filtre les vulnérabilités obsolètes (< 2020)
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            results = []
            for item in vulnerabilities:
                cve = item['cve']
                cve_id = cve['id']
                
                # Parsing de la description (on cherche la version anglaise)
                desc = "Pas de description."
                for d in cve.get('descriptions', []):
                    if d['lang'] == 'en':
                        desc = d['value']
                        break
                
                # Extraction du Score CVSS V3.1
                score = "N/A"
                severity = "UNKNOWN"
                metrics = cve.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    metric = metrics['cvssMetricV31'][0]['cvssData']
                    score = metric['baseScore']
                    severity = metric['baseSeverity']
                
                results.append({
                    'id': cve_id,
                    'score': score,
                    'severity': severity,
                    'description': desc
                })
            
            return results
            
        elif response.status_code == 403:
            print("    [!] Erreur API NVD : Rate limit atteint ou clé API requise.")
        elif response.status_code == 503:
            print("    [!] Erreur API NVD : Service indisponible.")

    except Exception as e:
        print(f"    [!] Exception connexion CVE : {e}")
    
    return []

def print_cve_results(cves):
    """Formatage et affichage des résultats CVE dans la console."""
    if not cves:
        print("    [-] Aucune CVE critique récente trouvée.")
        return

    print(f"    [!] {len(cves)} CVE(s) potentielle(s) identifiée(s) :")
    for cve in cves:
        sev_display = f"[{cve['severity']}]"
        
        print(f"    - {cve['id']} {sev_display} (Score: {cve['score']})")
        short_desc = (cve['description'][:90] + '...') if len(cve['description']) > 90 else cve['description']
        print(f"      {short_desc}")
    print("")
