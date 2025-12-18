import json
import time
import os
import html

def generate_report(engine):
    """
    Point d'entrée pour la génération des rapports.
    Dispatche vers le format de sortie configuré (JSON, HTML, TXT).
    """
    
    output_file = engine.config['output']
    fmt = engine.config['format']
    
    if not output_file:
        return

    # Agrégation des métadonnées du scan et des vulnérabilités trouvées
    data = {
        "scan_info": {
            "tool": "WAFMap v1.0",
            "target": engine.config['target'],
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "options": {
                "threads": engine.config['threads'],
                "level": engine.config['level'],
                "waf_bypass": engine.config['waf_bypass'],
                "crawl": engine.config['crawl']
            },
            "total_vulnerabilities": len(engine.vulnerabilities)
        },
        "vulnerabilities": engine.vulnerabilities
    }

    try:
        # Dispatch selon le format
        if fmt == 'json':
            save_json(data, output_file)
        elif fmt == 'html':
            save_html(data, output_file)
        else:
            save_txt(data, output_file)
            
        print(f"\n[+] Rapport sauvegardé avec succès : {output_file}")
        
    except Exception as e:
        print(f"[ERROR] Échec critique lors de l'écriture du rapport : {e}")

def save_json(data, filename):
    """Export des données brutes en JSON pour intégration possible avec d'autres outils."""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def save_txt(data, filename):
    """Génération d'un rapport textuel humainement lisible (format logs)."""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"=== RAPPORT DE PENTEST WAFMAP ===\n")
        f.write(f"Généré le : {data['scan_info']['date']}\n")
        f.write(f"Cible     : {data['scan_info']['target']}\n")
        f.write(f"Total Vuln: {data['scan_info']['total_vulnerabilities']}\n")
        f.write("=" * 50 + "\n\n")
        
        for idx, vuln in enumerate(data['vulnerabilities'], 1):
            f.write(f"[{idx}] TYPE: {vuln['type']}\n")
            f.write(f"    URL: {vuln['url']}\n")
            f.write(f"    PARAM: {vuln.get('parameter', 'N/A')}\n")
            f.write(f"    PAYLOAD: {vuln['payload']}\n")
            f.write(f"    DETAILS: {vuln['details']}\n")
            f.write("-" * 50 + "\n")

def save_html(data, filename):
    """
    Génération d'un rapport HTML interactif.
    NOTE DE SÉCURITÉ : Utilisation de html.escape() obligatoire sur les payloads
    pour éviter une XSS stockée lors de l'ouverture du rapport par l'auditeur.
    """
    
    # Construction du DOM pour les vulnérabilités
    vuln_html = ""
    if not data['vulnerabilities']:
        vuln_html = '<div class="empty-state">Aucune vulnérabilité détectée. La cible semble sécurisée.</div>'
    else:
        for i, vuln in enumerate(data['vulnerabilities']):
            # Assainissement des entrées utilisateur (payloads/details) avant injection dans le DOM
            safe_payload = html.escape(vuln['payload'])
            safe_details = html.escape(vuln['details'])
            
            vuln_html += f"""
            <div class="vuln-card">
                <div class="vuln-header">
                    <span class="vuln-id">#{i+1}</span>
                    <span class="vuln-title">{html.escape(vuln['type'])}</span>
                </div>
                <div class="vuln-body">
                    <div class="row"><strong>URL :</strong> <a href="{vuln['url']}" target="_blank">{html.escape(vuln['url'])}</a></div>
                    <div class="row"><strong>Paramètre :</strong> <code>{html.escape(str(vuln.get('parameter', 'N/A')))}</code></div>
                    <div class="row"><strong>Payload :</strong> <pre>{safe_payload}</pre></div>
                    <div class="row"><strong>Preuve :</strong> {safe_details}</div>
                </div>
            </div>
            """

    # Template HTML
    template = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rapport WAFMap - {data['scan_info']['target']}</title>
        <style>
            :root {{ --primary: #2c3e50; --accent: #e74c3c; --bg: #f4f6f9; --card-bg: #ffffff; --text: #333; }}
            body {{ font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 0; line-height: 1.6; }}
            .container {{ max_width: 1100px; margin: 0 auto; padding: 20px; }}
            
            /* Header */
            header {{ background: var(--primary); color: white; padding: 40px 20px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            h1 {{ margin: 0; font-size: 2.5rem; }}
            .meta {{ margin-top: 10px; font-size: 0.9rem; opacity: 0.8; }}
            
            /* Summary Box */
            .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: -30px auto 40px; max-width: 900px; }}
            .stat-card {{ background: var(--card-bg); padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }}
            .stat-num {{ display: block; font-size: 2.5rem; font-weight: bold; color: var(--accent); }}
            .stat-label {{ text-transform: uppercase; font-size: 0.8rem; color: #777; letter-spacing: 1px; }}
            
            /* Vulnerability Cards */
            .vuln-card {{ background: var(--card-bg); border-radius: 8px; margin-bottom: 20px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 5px solid var(--accent); }}
            .vuln-header {{ background: #fdfdfd; padding: 15px 20px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 15px; }}
            .vuln-id {{ background: #eee; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; font-weight: bold; color: #555; }}
            .vuln-title {{ font-size: 1.2rem; font-weight: 600; flex-grow: 1; }}
            .critical {{ background-color: var(--accent); }}
            
            .vuln-body {{ padding: 20px; }}
            .row {{ margin-bottom: 15px; }}
            .row strong {{ display: inline-block; width: 100px; color: #555; }}
            code {{ background: #f1f2f6; padding: 3px 6px; border-radius: 4px; color: #d63031; font-family: 'Consolas', monospace; }}
            pre {{ background: #2d3436; color: #dfe6e9; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Consolas', monospace; margin-top: 5px; }}
            a {{ color: #3498db; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            
            .empty-state {{ text-align: center; padding: 50px; background: white; border-radius: 8px; color: #27ae60; font-weight: bold; font-size: 1.2rem; }}
        </style>
    </head>
    <body>
        <header>
            <h1>Rapport de Sécurité WAFMap</h1>
            <div class="meta">Cible : {data['scan_info']['target']} | Date : {data['scan_info']['date']}</div>
        </header>
        
        <div class="container">
            <div class="summary">
                <div class="stat-card">
                    <span class="stat-num">{data['scan_info']['total_vulnerabilities']}</span>
                    <span class="stat-label">Vulnérabilités</span>
                </div>
                <div class="stat-card">
                    <span class="stat-num">{data['scan_info']['options']['level']}</span>
                    <span class="stat-label">Niveau Scan</span>
                </div>
                <div class="stat-card">
                    <span class="stat-num">{data['scan_info']['options']['threads']}</span>
                    <span class="stat-label">Threads</span>
                </div>
            </div>
            
            <h2>Détails des Détections</h2>
            {vuln_html}
        </div>
    </body>
    </html>
    """
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(template)
