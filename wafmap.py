import argparse
import sys
import os
from rich.console import Console
console = Console()

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from scanner.engine import Engine
except ImportError:
    try:
        from engine import Engine
    except ImportError:
        console.print(f"[bold red][!][ERREUR] CRITIQUE : Impossible de charger le moteur 'engine'. Vérifiez la structure des dossiers.[/bold red]")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="WAFMap: Outil de scan et bypass de WAF (Projet de Stage)")

    group_target = parser.add_argument_group('Cible')
    group_target.add_argument("--target", required=True, help="URL cible (ex: http://example.com)")
    
    group_output = parser.add_argument_group('Rapport')
    group_output.add_argument("--output", help="Chemin du fichier pour sauvegarder le rapport")
    group_output.add_argument("--format", default="txt", choices=["json", "txt", "html"], help="Format de sortie (défaut: txt)")
    group_output.add_argument("--verbose", action="store_true", help="Mode verbeux (logs de debug et stack traces)")

    group_http = parser.add_argument_group('Options HTTP')
    group_http.add_argument("--proxy", help="Proxy HTTP/HTTPS (ex: http://127.0.0.1:8080 pour Burp)")
    group_http.add_argument("--user-agent", help="Spoofing du User-Agent")
    group_http.add_argument("--headers", help="Fichier externe contenant des headers custom (Cookies, Auth...)")
    group_http.add_argument("--data", help="Données brutes pour forcer une requête POST")
    group_http.add_argument("--match-code", type=int, help="Validation manuelle : Code HTTP attendu")
    group_http.add_argument("--match-text", help="Validation manuelle : Chaîne attendue dans la réponse")

    group_config = parser.add_argument_group('Config')
    group_config.add_argument("--threads", type=int, default=20, help="Niveau de parallélisme (défaut 20)")
    group_config.add_argument("--timeout", type=int, default=5, help="Timeout socket en secondes")
    group_config.add_argument("--level", type=int, default=1, choices=[1, 2, 3], help="Intensité des tests (1=Rapide, 3=Exhaustif)")

    group_features = parser.add_argument_group('Modules')
    group_features.add_argument("--waf-only", action="store_true", help="Arrêter après la détection du WAF")
    group_features.add_argument("--crawl", action="store_true", help="Activer le spidering pour trouver des inputs")
    group_features.add_argument("--waf-bypass", action="store_true", help="Activer les techniques d'évasion (Tampering)")
    group_features.add_argument("--ports", help="Activer le scan de ports (liste séparée par virgules)")
    group_features.add_argument("--subdomains", action="store_true", help="Activer l'énumération de sous-domaines")
    group_features.add_argument("--api-scan", action="store_true", help="Activer la découverte d'endpoints API")
    group_features.add_argument("--cve", action="store_true", help="Rechercher les CVE publiques du WAF détecté")
    
    group_features.add_argument("--category", default=None, 
        choices=["all", "sqli", "xss", "ssrf", "ssti", "lfi", "cmdi", "nosqli", "csrf", "idor", "smuggling"],
        help="Limiter le scan à un type de vulnérabilité spécifique"
    )

    args = parser.parse_args()

    banner = r"""[bold cyan]
 __          __    _ __ _  __                  
 \ \        / /   /  _|  \/  |                 
  \ \  /\  / /_ _|  |_| \  / | __ _ _ __       
   \ \/  \/ / _` |   _| |\/| |/ _` | '_ \      
    \  /\  / (_| |  | | |  | | (_| | |_) |     
     \/  \/ \__,_|__| |_|  |_|\__,_| ___/      
                                   | |        
                   v1.0        	   |_|        
    [/bold cyan]"""
    console.print(banner)
    console.print("[italic grey]   > Outil de Pentesting WAF & Bypass Automatisé[/italic grey]\n")
    
    try:
        engine = Engine(args)
        engine.start_scan()
        
    except KeyboardInterrupt:
        console.print(f"[bold red]\n[!] Scan interrompu par l'utilisateur.[/bold red]")
        sys.exit(0)
    except Exception as e:
        print(f"[bold red]\n[ERREUR] Une erreur inattendue est survenue : {e}[/bold red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
