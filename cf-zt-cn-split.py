import requests
import os
import re

CF_EMAIL       = os.getenv('CLOUDFLARE_EMAIL', os.getenv('CF_EMAIL', ''))
CF_GLOBAL_KEY  = os.getenv('CLOUDFLARE_GLOBAL_KEY', os.getenv('CF_GLOBAL_KEY', ''))
CF_API_TOKEN   = os.getenv('CF_API_TOKEN', os.getenv('CLOUDFLARE_API_TOKEN', ''))
ACCOUNT_ID     = os.getenv('CLOUDFLARE_ACCOUNT_ID', os.getenv('CF_ACCOUNT_ID', ''))
PROFILE_ID     = os.getenv('CF_PROFILE_ID', '')
MODE           = os.getenv('MODE', 'exclude')
ALLOWED_MODES  = {'exclude', 'include'}

if not ACCOUNT_ID:
    raise ValueError('Missing ACCOUNT_ID')

HEADERS = {'Content-Type': 'application/json'}
if CF_EMAIL and CF_GLOBAL_KEY:
    HEADERS['X-Auth-Email'] = CF_EMAIL
    HEADERS['X-Auth-Key'] = CF_GLOBAL_KEY
elif CF_GLOBAL_KEY and not CF_EMAIL and not CF_API_TOKEN:
    HEADERS['X-Auth-Key'] = CF_GLOBAL_KEY
elif CF_API_TOKEN:
    if CF_API_TOKEN.startswith('cfk_'):
        HEADERS['X-Auth-Key'] = CF_API_TOKEN
        if CF_EMAIL:
            HEADERS['X-Auth-Email'] = CF_EMAIL
    else:
        HEADERS['Authorization'] = f'Bearer {CF_API_TOKEN}'
else:
    raise ValueError('Required Credentials missing')

if MODE not in ALLOWED_MODES:
    raise ValueError(f'Invalid MODE: {MODE}')

MAX_RULES       = 4000
TARGET_DOMAIN_N = 100

VALID_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
DOMAIN_URL      = 'https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt'
IP_URL          = 'https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt'

def ensure_masque_protocol():
    try:
        url = f'https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy'
        if PROFILE_ID:
            url += f'/{PROFILE_ID}'
        r = requests.get(url, headers=HEADERS, timeout=15)
        if r.status_code == 200:
            res = r.json()
            curr_proto = res.get('result', {}).get('tunnel_protocol')
            print(f'Current Zero Trust Tunnel Protocol: {curr_proto}')
            if curr_proto != 'masque':
                print('Updating Device Policy: Switching to MASQUE Protocol...')
                patch_r = requests.patch(url, json={'tunnel_protocol': 'masque'}, headers=HEADERS, timeout=15)
                if patch_r.status_code == 200 and patch_r.json().get('success'):
                    print('MASQUE Protocol Enabled Successfully!')
                else:
                    print(f'Masque patch response: {patch_r.status_code}')
            else:
                print('MASQUE Protocol is already Active.')
    except Exception as e:
        print(f'Check MASQUE error: {e}')

def get_cn_cidrs():
    r = requests.get(IP_URL, timeout=30)
    r.raise_for_status()
    cidrs = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')]
    print(f'IP CIDR count: {len(cidrs)}')
    return cidrs

def get_cn_domains():
    r = requests.get(DOMAIN_URL, timeout=30)
    r.raise_for_status()
    domains = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('DOMAIN-SUFFIX,'):
            line = line.replace('DOMAIN-SUFFIX,', '').strip()
        line = line.lstrip('.')
        if line and VALID_DOMAIN_RE.match(line):
            domains.append(f'*.{line}')
    unique = list(set(domains))
    print(f'Domain count: {len(unique)}')
    return unique

def update_split_tunnels(cidrs, domains):
    max_domains = min(TARGET_DOMAIN_N, len(domains))
    max_ips     = min(MAX_RULES - max_domains, len(cidrs))

    domain_entries = [{'host':    d,    'description': 'CN Domain'} for d in domains[:max_domains]]
    ip_entries     = [{'address': cidr, 'description': 'CN IP'} for cidr in cidrs[:max_ips]]
    routes = domain_entries + ip_entries

    print(f'Domain rules: {len(domain_entries)} | IP rules: {len(ip_entries)} | Total: {len(routes)}')

    if len(routes) > MAX_RULES:
        print('Total rules exceeded, truncating')
        routes = routes[:MAX_RULES]

    if PROFILE_ID:
        url = f'https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{PROFILE_ID}/{MODE}'
    else:
        url = f'https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}'

    resp = requests.put(url, json=routes, headers=HEADERS, timeout=30)
    if resp.status_code in (200, 204):
        print(f'Sync Successful! {len(routes)} routes | Mode: {MODE}')
    else:
        print(f'Failed {resp.status_code}: {resp.text}')
        resp.raise_for_status()

if __name__ == '__main__':
    print('Checking MASQUE protocol...')
    ensure_masque_protocol()
    print('Fetching CN Geo data...')
    cidrs   = get_cn_cidrs()
    domains = get_cn_domains()
    update_split_tunnels(cidrs, domains)
