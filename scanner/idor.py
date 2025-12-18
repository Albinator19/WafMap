def run_idor_test(engine, point, param_name, level, bypass):
    if param_name.lower() not in ['id', 'uid', 'user_id', 'account', 'order_id', 'profile']:
        return

    url = point['url']
    method = point['method']
    test_ids = ['1', '0', '1000', 'admin', '10']
    
    for tid in test_ids:
        data = {p: 'x' for p in point['parameters']} if method=='POST' else None
        params = {p: 'x' for p in point['parameters']} if method=='GET' else None
        
        if method=='POST': data[param_name] = tid
        else: params[param_name] = tid

        resp = engine._send_request(url, method=method, data=data, params=params)
        
        if resp and resp.status_code == 200:
            if tid in test_ids and len(resp.text) > 20:
                 if "not found" not in resp.text.lower() and "error" not in resp.text.lower():
                     engine.add_vulnerability(
                        "IDOR (Potentiel)", url, tid, 
                        f"Accès réussi à l'objet {tid} (Code 200).", parameter=param_name
                    )
