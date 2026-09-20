import requests
from urllib.parse import urljoin

API_ROOTS = [
    '', 
    '/api', '/api/v1', '/api/v2', '/api/v3', '/api/v4', '/api/v5',
    '/rest', '/rest/v1', '/rest/v2',
    '/v1', '/v2', '/v3', '/v4', '/beta', '/latest',
    '/public', '/private', '/internal',
    '/service', '/services', '/backend', 'rest/products', 'rest/items', 'rest/api',
    '/mobile', '/app', '/client', '/mobile/api',
    '/wp-json',       
    '/actuator',     
    '/graphql',       
    '/auth',         
    '/oauth',        
    '/sso'            
]

API_RESOURCES = [
    '', 
    '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger/index.html',
    '/swagger.json', '/swagger.yaml', '/swagger.yml',
    '/openapi.json', '/openapi.yaml', '/openapi.yml',
    '/api-docs', '/v2/api-docs', '/v3/api-docs',
    '/redoc', '/docs', '/doc', '/api/docs',
    '/graphql', '/graphiql', '/explorer',
    '/wsdl', 
    '/user', '/users', '/current_user', '/me', '/profile',
    '/login', '/signin', '/register', '/signup',
    '/auth/login', '/auth/token', '/oauth/token',
    '/sessions', '/logout', '/reset-password',   
    '/health', '/healthz', '/status', '/ping',
    '/metrics', '/info', '/version', '/env', '/config',
    '/actuator/health', '/actuator/info', '/actuator/env', 
    '/debug', '/trace',
    '/products', '/items', '/articles', '/posts',
    '/search', '/query', '/upload', '/files',
    '/orders', '/customers', '/settings', '/admin',
    '/notifications', '/messages', '/comments', '/products'
]

def detect_api(engine, base_url):
    print(f"[*] Recherche d'endpoints API sur {base_url}...")
    
    api_endpoints = []
    
    paths_to_test = []
    for root in API_ROOTS:
        for res in API_RESOURCES:
            path = f"{root}{res}".replace('//', '/')
            if path: 
                paths_to_test.append(path)
    
    paths_to_test = list(set(paths_to_test))

    for path in paths_to_test:
        url = urljoin(base_url, path)
        
        resp = engine._send_request(url, method="GET")
        
        if resp is not None:
            if resp.status_code in [200, 401, 403]:
                ctype = resp.headers.get('Content-Type', '').lower()
                
                if 'application/json' in ctype or 'application/xml' in ctype:
                    details = f"API confirmée (Code {resp.status_code}, Type {ctype})"
                    engine.add_vulnerability("API DISCOVERY", url, "N/A", details, parameter="N/A")
                    api_endpoints.append(url)
                elif resp.status_code == 200 and ('swagger' in url or 'graphql' in url):
                     details = f"Endpoint API potentiel (Code {resp.status_code})"
                     engine.add_vulnerability("API DISCOVERY", url, "N/A", details, parameter="N/A")
                     api_endpoints.append(url)
                     
    return api_endpoints
