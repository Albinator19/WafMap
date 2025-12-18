import requests
from urllib.parse import urljoin

# 1. Racines d'API 
API_ROOTS = [
    '', # Racine du site
    # Standards REST
    '/api', '/api/v1', '/api/v2', '/api/v3', '/api/v4', '/api/v5',
    '/rest', '/rest/v1', '/rest/v2',
    '/v1', '/v2', '/v3', '/v4', '/beta', '/latest',
    '/public', '/private', '/internal',
    '/service', '/services', '/backend', 'rest/products', 'rest/items', 'rest/api',
    # Spécifiques Mobile/App
    '/mobile', '/app', '/client', '/mobile/api',
    # Frameworks spécifiques
    '/wp-json',       # WordPress REST API
    '/actuator',      # Spring Boot
    '/graphql',       # GraphQL Root
    '/auth',          # Auth services
    '/oauth',         # OAuth roots
    '/sso'            # Single Sign On
]

# 2. Ressources et Fichiers 
API_RESOURCES = [
    '', # Pour tester la racine elle-même
    
    # Documentation & Spécifications
    '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger/index.html',
    '/swagger.json', '/swagger.yaml', '/swagger.yml',
    '/openapi.json', '/openapi.yaml', '/openapi.yml',
    '/api-docs', '/v2/api-docs', '/v3/api-docs',
    '/redoc', '/docs', '/doc', '/api/docs',
    '/graphql', '/graphiql', '/explorer', # Interfaces GraphQL
    '/wsdl', # SOAP
    
    # Authentification & Utilisateurs 
    '/user', '/users', '/current_user', '/me', '/profile',
    '/login', '/signin', '/register', '/signup',
    '/auth/login', '/auth/token', '/oauth/token',
    '/sessions', '/logout', '/reset-password',
    
    # Monitoring & Santé 
    '/health', '/healthz', '/status', '/ping',
    '/metrics', '/info', '/version', '/env', '/config',
    '/actuator/health', '/actuator/info', '/actuator/env', 
    '/debug', '/trace',
    
    # Données Métier 
    '/products', '/items', '/articles', '/posts',
    '/search', '/query', '/upload', '/files',
    '/orders', '/customers', '/settings', '/admin',
    '/notifications', '/messages', '/comments', '/products'
]

def detect_api(engine, base_url):
    """
    Tente de découvrir des endpoints API non documentés par force brute intelligente.
    Combine les racines (/api) et les ressources (/users).
    """
    print(f"[*] Recherche d'endpoints API sur {base_url}...")
    
    api_endpoints = []
    
    # Génération de la liste des chemins 
    paths_to_test = []
    for root in API_ROOTS:
        for res in API_RESOURCES:
            # Nettoyage des doubles slashes éventuels
            path = f"{root}{res}".replace('//', '/')
            if path: 
                paths_to_test.append(path)
    
    # Suppression des doublons
    paths_to_test = list(set(paths_to_test))

    for path in paths_to_test:
        url = urljoin(base_url, path)
        
        # Envoi de la requête via l'Engine pour gérer proxy, headers, timeouts, etc.
        resp = engine._send_request(url, method="GET")
        
        if resp:
            # 1. Vérification du Code HTTP
            # 200 OK est idéal, mais 401/403 indiquent souvent que la route existe mais est protégée
            if resp.status_code in [200, 401, 403]:
                ctype = resp.headers.get('Content-Type', '').lower()
                
                # 2. Validation stricte par Content-Type
                # Si le serveur renvoie du JSON ou XML, c'est très probablement une API
                if 'application/json' in ctype or 'application/xml' in ctype:
                    details = f"API confirmée (Code {resp.status_code}, Type {ctype})"
                    engine.add_vulnerability("API DISCOVERY", url, "N/A", details, parameter="N/A")
                    api_endpoints.append(url)
                
                # 3. Validation souple pour la documentation (Swagger) ou GraphQL
                # Ces pages peuvent être en HTML, donc on vérifie l'URL
                elif resp.status_code == 200 and ('swagger' in url or 'graphql' in url):
                     details = f"Endpoint API potentiel (Code {resp.status_code})"
                     engine.add_vulnerability("API DISCOVERY", url, "N/A", details, parameter="N/A")
                     api_endpoints.append(url)
                     
    return api_endpoints
