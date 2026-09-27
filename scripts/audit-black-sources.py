"""Read-only upstream directive inventory; never publishes or drops rules."""
import collections
import concurrent.futures
import json
import runpy

u = runpy.run_path('/tmp/ty-rule-updater-candidate.py')
keys = ['OpenAI', 'Claude', 'Gemini', 'YouTube', 'TikTok', 'Netflix', 'GitHub',
        'Google', 'Microsoft', 'Apple', 'Telegram', 'HK-Broker', 'ChinaMax']

def audit(key):
    url = f'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/{key}/{key}.list'
    try:
        data = u['fetch'](url).decode('utf-8-sig')
        counts = collections.Counter()
        for line in data.splitlines():
            line = line.strip()
            if line and not line.startswith(('#', '//')):
                counts[line.split(',')[0]] += 1
        return {'source': key, 'directives': dict(counts)}
    except Exception as exc:
        return {'source': key, 'error': str(exc)}

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    for result in pool.map(audit, keys):
        print(json.dumps(result), flush=True)
