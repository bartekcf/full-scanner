#!/usr/bin/env python3
"""Offline model bridge; stdin contains a single saved scan, stdout the sanitized model."""
import json
import sys
from reporting.catalog import Catalog
from reporting.model import build, brief_cve_candidates

MAX_INPUT=64*1024*1024

def main():
    catalog=Catalog()
    if sys.argv[1:]==['--validate']:
        print(json.dumps({'rules':len(catalog.rules),'schema_version':1}));return
    if sys.argv[1:] not in ([], ['--brief']):raise ValueError('Invalid preparation option')
    brief=sys.argv[1:]==['--brief']
    raw=sys.stdin.buffer.read(MAX_INPUT+1)
    if len(raw)>MAX_INPUT:raise ValueError('Input exceeds 64 MiB')
    scan=json.loads(raw)
    model=build(scan,catalog)
    if brief:
        model['brief_cves']=brief_cve_candidates(scan)
    sys.stdout.write(json.dumps(model,ensure_ascii=False,allow_nan=False))

if __name__=='__main__':
    try:main()
    except Exception as exc:
        # Never echo source values, paths, evidence or stack traces to batch logs.
        print('Model preparation failed: '+type(exc).__name__,file=sys.stderr)
        sys.exit(1)
