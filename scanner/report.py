import json
import time
import html


def generate_report(engine):
    output_file = engine.config['output']
    fmt = engine.config['format']

    if not output_file:
        return

    confirmed = [v for v in engine.vulnerabilities if v.get('confidence') == 'Confirmée']
    to_verify = [v for v in engine.vulnerabilities if v.get('confidence') != 'Confirmée']

    data = {
        "scan_info": {
            "tool": "WAFMap v1.1",
            "target": engine.config['target'],
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "waf_detected": engine.detected_waf_name,
            "options": {
                "threads": engine.config['threads'],
                "level": engine.config['level'],
                "waf_bypass": engine.config['waf_bypass'],
                "crawl": engine.config['crawl']
            },
            "total_confirmed": len(confirmed),
            "total_to_verify": len(to_verify),
            "total_recon": len(engine.recon_findings)
        },
        "vulnerabilities_confirmed": confirmed,
        "vulnerabilities_to_verify": to_verify,
        "recon_findings": engine.recon_findings
    }

    try:
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
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def _write_vuln_block(f, vulns, title):
    f.write(f"--- {title} ({len(vulns)}) ---\n\n")
    for idx, vuln in enumerate(vulns, 1):
        f.write(f"[{idx}] TYPE: {vuln['type']}\n")
        f.write(f"    URL: {vuln['url']}\n")
        f.write(f"    PARAM: {vuln.get('parameter', 'N/A')}\n")
        f.write(f"    PAYLOAD: {vuln['payload']}\n")
        f.write(f"    DETAILS: {vuln['details']}\n")
        f.write(f"    CONFIANCE: {vuln.get('confidence', 'N/A')}\n")
        f.write("-" * 50 + "\n")
    f.write("\n")


def save_txt(data, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=== RAPPORT DE PENTEST WAFMAP ===\n")
        f.write(f"Généré le : {data['scan_info']['date']}\n")
        f.write(f"Cible     : {data['scan_info']['target']}\n")
        f.write(f"WAF       : {data['scan_info']['waf_detected']}\n")
        f.write(f"Confirmées: {data['scan_info']['total_confirmed']}\n")
        f.write(f"A vérifier: {data['scan_info']['total_to_verify']}\n")
        f.write(f"Recon     : {data['scan_info']['total_recon']}\n")
        f.write("=" * 50 + "\n\n")

        _write_vuln_block(f, data['vulnerabilities_confirmed'], "VULNÉRABILITÉS CONFIRMÉES")
        _write_vuln_block(f, data['vulnerabilities_to_verify'], "A VÉRIFIER MANUELLEMENT")

        f.write(f"--- FINDINGS DE RECONNAISSANCE ({len(data['recon_findings'])}) ---\n\n")
        for idx, finding in enumerate(data['recon_findings'], 1):
            f.write(f"[{idx}] TYPE: {finding['type']}\n")
            f.write(f"    URL: {finding['url']}\n")
            f.write(f"    DETAILS: {finding['details']}\n")
            f.write("-" * 50 + "\n")


def _vuln_card_html(i, vuln, border_class):
    safe_payload = html.escape(str(vuln['payload']))
    safe_details = html.escape(str(vuln['details']))
    return f"""
    <div class="vuln-card {border_class}">
        <div class="vuln-header">
            <span class="vuln-id">#{i + 1}</span>
            <span class="vuln-title">{html.escape(vuln['type'])}</span>
            <span class="badge {border_class}">{html.escape(str(vuln.get('confidence', 'N/A')))}</span>
        </div>
        <div class="vuln-body">
            <div class="row"><strong>URL :</strong> <a href="{html.escape(vuln['url'])}" target="_blank">{html.escape(vuln['url'])}</a></div>
            <div class="row"><strong>Paramètre :</strong> <code>{html.escape(str(vuln.get('parameter', 'N/A')))}</code></div>
            <div class="row"><strong>Payload :</strong> <pre>{safe_payload}</pre></div>
            <div class="row"><strong>Preuve :</strong> {safe_details}</div>
        </div>
    </div>
    """


def _recon_card_html(i, finding):
    safe_details = html.escape(str(finding['details']))
    return f"""
    <div class="vuln-card recon">
        <div class="vuln-header">
            <span class="vuln-id">#{i + 1}</span>
            <span class="vuln-title">{html.escape(finding['type'])}</span>
            <span class="badge recon">Reconnaissance</span>
        </div>
        <div class="vuln-body">
            <div class="row"><strong>URL :</strong> <a href="{html.escape(finding['url'])}" target="_blank">{html.escape(finding['url'])}</a></div>
            <div class="row"><strong>Détails :</strong> {safe_details}</div>
        </div>
    </div>
    """


def save_html(data, filename):
    confirmed_html = "".join(_vuln_card_html(i, v, "confirmed") for i, v in enumerate(data['vulnerabilities_confirmed']))
    to_verify_html = "".join(_vuln_card_html(i, v, "to-verify") for i, v in enumerate(data['vulnerabilities_to_verify']))
    recon_html = "".join(_recon_card_html(i, f) for i, f in enumerate(data['recon_findings']))

    if not confirmed_html:
        confirmed_html = '<div class="empty-state">Aucune vulnérabilité confirmée.</div>'
    if not to_verify_html:
        to_verify_html = '<div class="empty-state">Rien à vérifier manuellement.</div>'
    if not recon_html:
        recon_html = '<div class="empty-state">Aucun finding de reconnaissance.</div>'

    template = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rapport WAFMap - {html.escape(str(data['scan_info']['target']))}</title>
        <style>
            :root {{ --primary: #2c3e50; --accent: #e74c3c; --warn: #f39c12; --recon: #3498db; --bg: #f4f6f9; --card-bg: #ffffff; --text: #333; }}
            body {{ font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 0; line-height: 1.6; }}
            .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
            header {{ background: var(--primary); color: white; padding: 40px 20px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            h1 {{ margin: 0; font-size: 2.5rem; }}
            .meta {{ margin-top: 10px; font-size: 0.9rem; opacity: 0.8; }}
            .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: -30px auto 40px; max-width: 900px; }}
            .stat-card {{ background: var(--card-bg); padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }}
            .stat-num {{ display: block; font-size: 2.5rem; font-weight: bold; color: var(--accent); }}
            .stat-label {{ text-transform: uppercase; font-size: 0.8rem; color: #777; letter-spacing: 1px; }}
            h2 {{ margin-top: 40px; }}
            .vuln-card {{ background: var(--card-bg); border-radius: 8px; margin-bottom: 20px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 5px solid var(--accent); }}
            .vuln-card.to-verify {{ border-left-color: var(--warn); }}
            .vuln-card.recon {{ border-left-color: var(--recon); }}
            .vuln-header {{ background: #fdfdfd; padding: 15px 20px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 15px; }}
            .vuln-id {{ background: #eee; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; font-weight: bold; color: #555; }}
            .vuln-title {{ font-size: 1.2rem; font-weight: 600; flex-grow: 1; }}
            .badge {{ font-size: 0.75rem; font-weight: bold; padding: 3px 10px; border-radius: 12px; color: white; }}
            .badge.confirmed {{ background: var(--accent); }}
            .badge.to-verify {{ background: var(--warn); }}
            .badge.recon {{ background: var(--recon); }}
            .vuln-body {{ padding: 20px; }}
            .row {{ margin-bottom: 15px; }}
            .row strong {{ display: inline-block; width: 100px; color: #555; }}
            code {{ background: #f1f2f6; padding: 3px 6px; border-radius: 4px; color: #d63031; font-family: 'Consolas', monospace; }}
            pre {{ background: #2d3436; color: #dfe6e9; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Consolas', monospace; margin-top: 5px; white-space: pre-wrap; word-break: break-all; }}
            a {{ color: #3498db; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            .empty-state {{ text-align: center; padding: 50px; background: white; border-radius: 8px; color: #27ae60; font-weight: bold; font-size: 1.2rem; }}
        </style>
    </head>
    <body>
        <header>
            <h1>Rapport de Sécurité WAFMap</h1>
            <div class="meta">Cible : {html.escape(str(data['scan_info']['target']))} | WAF : {html.escape(str(data['scan_info']['waf_detected']))} | Date : {data['scan_info']['date']}</div>
        </header>

        <div class="container">
            <div class="summary">
                <div class="stat-card">
                    <span class="stat-num">{data['scan_info']['total_confirmed']}</span>
                    <span class="stat-label">Confirmées</span>
                </div>
                <div class="stat-card">
                    <span class="stat-num">{data['scan_info']['total_to_verify']}</span>
                    <span class="stat-label">A vérifier</span>
                </div>
                <div class="stat-card">
                    <span class="stat-num">{data['scan_info']['total_recon']}</span>
                    <span class="stat-label">Reconnaissance</span>
                </div>
            </div>

            <h2>Vulnérabilités confirmées</h2>
            {confirmed_html}

            <h2>A vérifier manuellement</h2>
            {to_verify_html}

            <h2>Findings de reconnaissance</h2>
            {recon_html}
        </div>
    </body>
    </html>
    """

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(template)
