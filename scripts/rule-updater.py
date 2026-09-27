#!/usr/bin/env python3
"""Bounded, fail-closed updater. Only this fixed catalogue can fetch remote data."""
import collections
import datetime
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import sys
import subprocess
import time
import urllib.request

ROOT = pathlib.Path(os.environ.get('TY_RULE_PACKAGES_DIR', '/var/lib/tygateway/rule-packages'))
CATEGORY_SOURCES = {'AI':['openai','anthropic','google-gemini'], 'YouTube':['youtube'], 'TikTok':['tiktok'], 'Netflix':['netflix'], 'GitHub':['github'], 'Google':['google'], 'Microsoft':['microsoft'], 'Apple':['apple'], 'Telegram':['telegram']}
CATEGORIES = ['China', 'HK-Broker'] + list(CATEGORY_SOURCES) + ['Final']
BROKER_SOURCE = 'https://raw.githubusercontent.com/Arthur-vx/broker-rules/main/Broker.list'
NAMES = {'managed_loyal': 'Loyalsoldier 综合分流', 'managed_meta': 'MetaCubeX 综合分流', 'managed_gfw': 'GFWList + 服务分类', 'managed_geo': 'GeoIP + 服务分类'}

def fetch(url):
    if not url.startswith('https://raw.githubusercontent.com/'):
        raise ValueError('source is not allowed')
    req = urllib.request.Request(url, headers={'User-Agent': 'TY-Gateway-Rules/1'})
    with urllib.request.urlopen(req, timeout=45) as response:
        if not response.url.startswith('https://raw.githubusercontent.com/'):
            raise ValueError('unexpected redirect')
        data = response.read(32 * 1024 * 1024 + 1)
    if not data or len(data) > 32 * 1024 * 1024:
        raise ValueError('empty or oversized source')
    return data

def varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        b = data[pos]; pos += 1
        value |= (b & 127) << shift
        if b < 128:
            return value, pos
    raise ValueError('invalid protobuf integer')

def fields(data):
    pos = 0
    while pos < len(data):
        tag, pos = varint(data, pos)
        if tag & 7 == 0:
            value, pos = varint(data, pos)
        elif tag & 7 == 2:
            size, pos = varint(data, pos)
            if pos + size > len(data): raise ValueError('truncated protobuf')
            value = data[pos:pos+size]; pos += size
        else:
            raise ValueError('unsupported protobuf field')
        yield tag >> 3, value

def geosite(data):
    result = {}
    for tag, entry in fields(data):
        if tag != 1: raise ValueError('unsupported geosite entry')
        name, domains = '', []
        for field, value in fields(entry):
            if field == 1: name = value.decode().lower()
            elif field == 2:
                domain = dict(fields(value))
                kind = {0:'domain_keyword', 1:'domain_regex', 2:'domain_suffix', 3:'domain'}.get(domain.get(1, 0))
                if not kind: raise ValueError('unsupported domain type')
                domains.append((kind, domain[2].decode()))
        if not name or not domains: raise ValueError('empty geosite category')
        result[name] = domains
    return result

def parse_list(data, style, skipped=None):
    result = []
    for line in data.decode('utf-8-sig').splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//')): continue
        if style == 'cidr':
            network = ipaddress.ip_network(line, strict=False)
            if network.version == 4: result.append(('cidr', str(network)))
            continue
        if style == 'domain':
            result.append(('domain_suffix', line)); continue
        parts = line.split(',')
        # Only the explicitly labelled compatibility build may omit ASN rules.
        if parts[0] == 'IP-ASN' and skipped is not None:
            if len(parts) not in (2, 3) or not parts[1].isdigit() or not 0 < int(parts[1]) <= 4294967295:
                raise ValueError('invalid IP-ASN rule')
            if len(parts) == 3 and parts[2] != 'no-resolve':
                raise ValueError('unsupported IP-ASN arguments')
            skipped['IP-ASN'] = skipped.get('IP-ASN', 0) + 1
            continue
        kind = {'DOMAIN':'domain','DOMAIN-SUFFIX':'domain_suffix','DOMAIN-KEYWORD':'domain_keyword','DOMAIN-REGEX':'domain_regex','IP-CIDR':'cidr','IP-CIDR6':'cidr'}.get(parts[0])
        if not kind or len(parts)<2: raise ValueError('unsupported rule directive: '+parts[0])
        if len(parts)>2 and parts[2:] != ['no-resolve']: raise ValueError('unsupported rule arguments')
        if kind=='cidr':
            network=ipaddress.ip_network(parts[1], strict=False)
            if network.version==6: continue  # Explicit IPv4-only product policy.
        result.append((kind,parts[1]))
    return result

def pack(profile, groups, sources):
    rules, counts, categories = [], {}, []
    for rank,(category, action, entries) in enumerate(groups):
        if not entries: raise ValueError('empty category '+category)
        counts[category] = len(entries)
        if category in CATEGORIES: categories.append(category)
        grouped = collections.defaultdict(set)
        for kind,value in entries:
            if not value or len(value)>4096 or any(c in value for c in '\n\r\x00'):
                raise ValueError('invalid rule value')
            if kind in ('domain','domain_suffix') and not re.fullmatch(r'[A-Za-z0-9_\-.]+',value):
                raise ValueError('invalid domain in '+category)
            if kind=='domain_regex': re.compile(value)
            elif ',' in value: raise ValueError('invalid comma in match')
            grouped[kind].add(value)
        for kind,values in sorted(grouped.items()):
            values=sorted(values)
            size=1 if kind=='domain_regex' else 512
            for start in range(0,len(values),size):
                rules.append({'id':f'{profile}-{rank}-{kind}-{start}', 'source':profile, 'source_type':'provider','category':category,'match_type':kind,'match_value':','.join(values[start:start+size]),'action':action,'priority':200+rank,'enabled':True})
    fallback='DIRECT' if profile=='managed_gfw' else 'PROXY'
    rules.append({'id':profile+'-fallback','source':profile,'source_type':'provider','category':'Final','match_type':'all','match_value':'','action':fallback,'priority':9999,'enabled':True})
    counts['Final'] = 1
    missing = [category for category in CATEGORIES if category not in categories and category != 'Final']
    if missing: raise ValueError('missing required categories: '+', '.join(missing))
    categories = CATEGORIES.copy()
    payload={'format':1,'category_schema':3,'profile':profile,'name':NAMES[profile],'categories':categories,'counts':counts,'sources':sources,'rules':rules,'fallback':fallback,'ipv4_only':True}
    raw=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    if len(raw)>6*1024*1024 or len(rules)>12000: raise ValueError('compiled package exceeds device budget')
    payload['version']=hashlib.sha256(raw).hexdigest()
    return payload

def build(profile):
    if profile not in NAMES: raise ValueError('unsupported profile')
    sources=[]
    omissions=[]
    def get(url):
        data=fetch(url); sources.append({'url':url,'sha256':hashlib.sha256(data).hexdigest()}); return data
    raw='https://raw.githubusercontent.com/'
    groups=[]
    if profile in NAMES:
        # User-selected aggregate; keep upstream provenance and precede China.
        broker = parse_list(get(BROKER_SOURCE), 'clash')
        if not broker: raise ValueError('empty HK-Broker source')
        groups.append(('HK-Broker', 'PROXY', broker))
    if profile in NAMES:
        url=raw+('MetaCubeX/meta-rules-dat/release/geosite.dat' if profile=='managed_meta' else 'Loyalsoldier/v2ray-rules-dat/release/geosite.dat')
        db=geosite(get(url))
        for category,keys in CATEGORY_SOURCES.items():
            for key in keys:
                if not db.get(key): raise ValueError('missing required category component: '+key)
            entries=[entry for key in keys for entry in db.get(key,[])]
            action='DIRECT' if category in ('Microsoft','Apple') else 'PROXY'
            groups.append((category,action,entries))
        domestic=parse_list(get(raw+'Loyalsoldier/geoip/release/text/cn.txt'),'cidr')
        if not db.get('cn'): raise ValueError('missing China domains')
        domestic += db['cn']
        groups.append(('China','DIRECT',domestic))
    if profile=='managed_gfw':
        gfw = parse_list(get(raw+'Loyalsoldier/v2ray-rules-dat/release/gfw.txt'),'domain')
        if not gfw: raise ValueError('empty GFW domain set')
        groups.append(('GFW','PROXY',gfw))
    return pack(profile,groups,sources)

def atomic(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix(path.suffix+'.tmp')
    with open(temp,'w',encoding='utf-8') as f:
        json.dump(data,f,ensure_ascii=False,separators=(',',':')); f.flush(); os.fsync(f.fileno())
    os.replace(temp,path)

def read(path):
    try: return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError: return {}

def main():
    ROOT.mkdir(parents=True,exist_ok=True)
    import fcntl
    with open(ROOT/'worker.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        for profile in NAMES:
            current=ROOT/(profile+'.json'); status_path=ROOT/(profile+'.status.json'); request=ROOT/(profile+'.request')
            previous=read(current); status=read(status_path); now=time.time()
            requested=request.exists()
            if now-status.get('checked_at',0)<(300 if requested else 86400): continue
            if requested: request.unlink(missing_ok=True)
            status.update({'profile':profile,'name':NAMES[profile],'state':'updating','checked_at':now})
            atomic(status_path,status)
            try:
                candidate=build(profile)
                validator=os.environ.get('TY_RULE_VALIDATOR','/usr/local/bin/ty-rule-validator')
                result=subprocess.run([validator],input=json.dumps(candidate).encode(),capture_output=True,timeout=60)
                if result.returncode: raise ValueError('dae conversion validation failed: '+result.stderr.decode(errors='replace')[:160])
                if previous and previous.get('category_schema') == candidate.get('category_schema'):
                    for category,count in previous['counts'].items():
                        new=candidate['counts'].get(category,0)
                        if new<count*.65 or new>max(1000,count*2): raise ValueError('abnormal category change: '+category)
                candidate['published_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
                # Archive before publication. Keep the two most recent versions.
                archive=ROOT/'versions'/profile
                atomic(archive/(candidate['version']+'.json'),candidate)
                atomic(current,candidate)
                for old in sorted(archive.glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True)[2:]: old.unlink()
                status.update({'state':'ready','version':candidate['version'],'error':'','published_at':candidate['published_at']})
            except Exception as e:
                status.update({'state':'failed','error':str(e)[:240]})
            atomic(status_path,status)
            print(profile,status['state'],status.get('error',''),flush=True)

if __name__=='__main__': main()
