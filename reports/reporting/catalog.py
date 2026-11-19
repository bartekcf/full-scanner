"""Validated, declarative knowledge catalog. No executable expressions."""
import re
import string
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit
import yaml

ROOT = Path(__file__).resolve().parents[2] / 'knowledge'

def name(value):
    return ' '.join(unicodedata.normalize('NFKC', str(value or '')).split()).casefold()

def identifier(value):
    return str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else ''

def web_url(value):
    if not isinstance(value, str): return False
    try:
        u = urlsplit(value)
        return u.scheme in ('https', 'http') and bool(u.hostname) and not u.username and not u.password
    except ValueError:
        return False

class UniqueLoader(yaml.SafeLoader):
    pass

def mapping(loader, node, deep=False):
    result = {}
    for k, v in node.value:
        key = loader.construct_object(k, deep=deep)
        if key in result: raise ValueError('Duplicate YAML key')
        result[key] = loader.construct_object(v, deep=deep)
    return result
UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)

class Catalog:
    def __init__(self, root=ROOT):
        self.rules, self.refs, self.pairs = {}, {}, {}
        docs = []
        for path in sorted(Path(root).glob('*.yaml')):
            if path.stat().st_size > 1_000_000: raise ValueError('Catalog file too large')
            data = yaml.load(path.read_text(encoding='utf-8'), Loader=UniqueLoader)
            if not isinstance(data, dict) or type(data.get('schema_version')) is not int or data['schema_version'] != 1:
                raise ValueError('Unsupported knowledge schema')
            docs.append(data)
        policies = [d for d in docs if d.get('kind') == 'reporting_policy']
        copies = [d for d in docs if d.get('kind') == 'report_copy']
        if len(policies) != 1 or len(copies) != 1: raise ValueError('Expected policy and copy')
        self.policy, self.copy = policies[0], copies[0]
        p = self.policy
        if set(p['priorities']) != {'urgent','review','improve','info'}: raise ValueError('Invalid priorities')
        ranks=[]
        for v in p['priorities'].values():
            if type(v.get('rank')) is not int or not isinstance(v.get('label'), str): raise ValueError('Invalid priority')
            ranks.append(v['rank'])
        if len(set(ranks)) != len(ranks): raise ValueError('Duplicate ranks')
        for v in p['groups'].values():
            if type(v.get('order')) is not int or not isinstance(v.get('title'), str): raise ValueError('Invalid group')
        expected_matching = {'strategy':'exact_variant_then_consistent_plugin_and_name','normalize_names':['unicode_nfkc','trim','collapse_whitespace','casefold'],'allow_plugin_only_if_single_unambiguous_rule':False,'reject_conflicting_identifiers':True,'unknown_rule':'preserve_and_flag'}
        if p.get('matching') != expected_matching: raise ValueError('Unsupported matching policy')
        for d in docs:
            if d.get('kind') in ('reporting_policy','report_copy'): continue
            if d.get('source') != 'zap' or not isinstance(d.get('rules'),list): raise ValueError('Invalid rule file')
            for r in d['rules']:
                required=['key','group','title','default_priority','verification_status','placement','observation','impact','recommendation','verification','limitations']
                if any(not isinstance(r.get(k),str) or not r[k] for k in required): raise ValueError('Invalid rule fields')
                if r['key'] in self.rules: raise ValueError('Duplicate rule key')
                if r['group'] not in p['groups'] or r['default_priority'] not in p['priorities']: raise ValueError('Unknown group or priority')
                if r['placement'] not in ('main','technical'): raise ValueError('Invalid placement')
                if r['verification_status'] not in ('passive_observation','unverified_risk','metadata','context_required'): raise ValueError('Invalid verification status')
                if not isinstance(r.get('evidence_fields'),list) or not all(isinstance(x,str) for x in r['evidence_fields']): raise ValueError('Invalid evidence fields')
                if not isinstance(r.get('references'),list) or not all(web_url(x) for x in r['references']): raise ValueError('Invalid references')
                m=r.get('match',{})
                for field in ('plugin_ids','alert_refs','names'):
                    if not isinstance(m.get(field),list) or not m[field] or not all(isinstance(x,str) and x for x in m[field]): raise ValueError('Invalid matching fields')
                for ref in m['alert_refs']:
                    if ref in self.refs: raise ValueError('Ambiguous alertRef')
                    self.refs[ref]=r
                for plugin in m['plugin_ids']:
                    for n in m['names']:
                        pair=(plugin,name(n))
                        if pair in self.pairs: raise ValueError('Ambiguous plugin/name')
                        self.pairs[pair]=r
                self.rules[r['key']]=r
        allowed_when={'scanner_severity_in','verification_status_not','rule_key_in','reviewer_confirmed_sensitive_context','reviewer_confirmed_sensitive_cookie','unmapped'}
        keys=set()
        for o in p['priority_overrides']:
            if o['key'] in keys: raise ValueError('Duplicate override')
            keys.add(o['key'])
            if set(o['when'])-allowed_when: raise ValueError('Unknown override condition')
            if set(o)-{'key','when','set_priority','set_placement','meaning'}: raise ValueError('Unknown override action')
            if 'set_priority' in o and o['set_priority'] not in p['priorities']: raise ValueError('Invalid override priority')
            if 'set_placement' in o and o['set_placement'] not in ('main','technical'): raise ValueError('Invalid override placement')
            for k,v in o['when'].items():
                if k.endswith('_in'):
                    if not isinstance(v,list) or not all(isinstance(x,str) for x in v): raise ValueError('Invalid override list')
                    if k=='rule_key_in' and any(x not in self.rules for x in v): raise ValueError('Unknown override rule')
                elif k in ('unmapped','reviewer_confirmed_sensitive_context','reviewer_confirmed_sensitive_cookie'):
                    if type(v) is not bool: raise ValueError('Invalid override flag')
                elif not isinstance(v,str): raise ValueError('Invalid override value')
        if p['fallback']['group'] not in p['groups'] or p['fallback']['priority'] not in p['priorities']: raise ValueError('Invalid fallback')
        if self.copy['report'].get('optional_extension_default') is not False: raise ValueError('Optional extension must be disabled')
        for k in ('email','website','phone','legal_name','address','nip','krs'):
            if self.copy['brand'].get(k) is not None and not isinstance(self.copy['brand'][k],str): raise ValueError('Invalid brand')
        if self.copy['brand'].get('website') and not web_url(self.copy['brand']['website']): raise ValueError('Invalid brand website')
        def placeholders(obj):
            if isinstance(obj,dict):
                for v in obj.values(): placeholders(v)
            elif isinstance(obj,list):
                for v in obj: placeholders(v)
            elif isinstance(obj,str):
                for _,field,fmt,conv in string.Formatter().parse(obj):
                    if field is not None and (field not in {'date','target','priority_items','areas','checks'} or fmt or conv): raise ValueError('Unknown placeholder')
        for doc in docs: placeholders(doc)

    def match(self, alert):
        ref,plugin,n = identifier(alert.get('alertRef')),identifier(alert.get('pluginId')),name(alert.get('name'))
        pair=self.pairs.get((plugin,n))
        if ref:
            rule=self.refs.get(ref)
            if not rule: return None,'unknown_ref'
            if plugin and plugin not in rule['match']['plugin_ids']: return None,'conflicting_plugin'
            if pair and pair['key']!=rule['key']: return None,'conflicting_name'
            # A known name belonging to another rule is contradictory, including a different plugin.
            named={r['key'] for r in self.rules.values() if n in [name(v) for v in r['match']['names']]}
            if named and rule['key'] not in named: return None,'conflicting_name'
            return rule,'exact_ref'
        return (pair,'plugin_and_name') if pair else (None,'unknown_rule')
