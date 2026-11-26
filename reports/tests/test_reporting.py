import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import yaml
from reporting.catalog import Catalog, ROOT, name
from reporting.model import build, brief_cve_candidates
from reporting.privacy import safe_url, extract, csp, OMITTED

C=Catalog()
def alert(key='csp_missing',**kwargs):
 r=C.rules[key]
 a={'pluginId':r['match']['plugin_ids'][0],'alertRef':r['match']['alert_refs'][0],'name':r['match']['names'][0],'risk':'Medium','confidence':'Low','url':'https://example.org/','evidence':''}
 a.update(kwargs);return a
def scan(alerts=None,**kwargs):
 d={'scan_id':'test-scan','url':'https://example.org/','status':'completed','created_at':'2026-11-17T10:00:00Z','findings':[],'raw_zap':{'alerts':alerts or []},'checks':[{'check':'owasp_zap_passive','status':'completed'}]}
 d.update(kwargs);return d

def variants(m):return [v for g in m['findings'] for v in g['variants']]+m['technical_observations']

class CatalogTests(unittest.TestCase):
 def test_every_rule_by_ref_and_pair(self):
  for key,r in C.rules.items():
   with self.subTest(key=key):
    a=alert(key);self.assertEqual(C.match(a)[0]['key'],key)
    a.pop('alertRef');self.assertEqual(C.match(a)[0]['key'],key)
 def test_int_identifiers(self):
  a=alert('nosniff_missing',pluginId=10021,alertRef=10021)
  self.assertEqual(C.match(a)[0]['key'],'nosniff_missing')
 def test_unicode_names(self):
  a=alert('csp_missing',alertRef='',name='  CONTENT\u00a0Security  Policy (CSP) Header Not Set  ')
  self.assertEqual(C.match(a)[0]['key'],'csp_missing')
  self.assertEqual(name('ＳＴＲＡＳＳＥ'),name('straße'))
 def test_conflicts(self):
  self.assertIsNone(C.match(alert('csp_missing',pluginId='10055'))[0])
  self.assertIsNone(C.match(alert('csp_script_inline',name='CSP: style-src unsafe-inline'))[0])
 def test_unknown_ref_not_guessed(self):
  self.assertIsNone(C.match(alert('csp_missing',alertRef='10038-999'))[0])
 def test_localized_exact_ref(self):
  self.assertEqual(C.match(alert('csp_missing',name='Brak polityki'))[0]['key'],'csp_missing')
 def test_no_plugin_only(self):
  for plugin in ('10055','10038','10020','10054','10035','10036','20020'):
   self.assertIsNone(C.match({'pluginId':plugin})[0])
 def test_invalid_catalog(self):
  for mutation in ('priority','reference','placeholder','duplicate','override','group','type','yaml_duplicate'):
   with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as folder:
    for p in ROOT.glob('*.yaml'):Path(folder,p.name).write_text(p.read_text())
    p=Path(folder,'csp.yaml');d=yaml.safe_load(p.read_text())
    if mutation=='priority':d['rules'][0]['default_priority']='critical'
    if mutation=='reference':d['rules'][0]['references']=['file:///etc/passwd']
    if mutation=='placeholder':d['rules'][0]['title']='{unknown}'
    if mutation=='duplicate':d['rules'].append(d['rules'][0])
    if mutation=='group':d['rules'][0]['group']='bad'
    if mutation=='type':d['rules'][0]['title']=3
    if mutation=='override':
     q=Path(folder,'policy.yaml');pol=yaml.safe_load(q.read_text());pol['priority_overrides'][0]['when']['eval']='bad';q.write_text(yaml.safe_dump(pol))
    p.write_text(yaml.safe_dump(d))
    if mutation=='yaml_duplicate':p.write_text('schema_version: 1\nschema_version: 1\n')
    with self.assertRaises((ValueError,KeyError)):Catalog(folder)

class ModelTests(unittest.TestCase):
 def test_priority_not_confidence(self):
  m=build(scan([alert('php_known',risk='High',confidence='Low',evidence='PHP/5.6.5')]),C)
  self.assertEqual(m['findings'][0]['priority'],'urgent')
  self.assertEqual(variants(m)[0]['scanner_confidences'],['low'])
 def test_unknown_risk(self):
  m=build(scan([alert('csp_missing',risk='mystery')]),C)
  self.assertEqual(variants(m)[0]['scanner_risks'],[None])
 def test_unknown_placements(self):
  for risk,place in [('High','main'),('Medium','main'),('Low','technical'),('Informational','technical')]:
   m=build(scan([alert(pluginId='999',alertRef='999',name='New rule',risk=risk,evidence='secret=secret42')]),C)
   self.assertEqual(variants(m)[0]['placement'],place)
   self.assertNotIn('secret42',json.dumps(m))
 def test_missing_vs_empty(self):
  a=scan();del a['findings']
  self.assertFalse(build(a,C)['coverage']['fields_present']['findings'])
  self.assertTrue(build(scan(),C)['coverage']['fields_present']['findings'])
 def test_partial_no_findings(self):
  m=build(scan(checks=[{'check':'single_http_get','status':'completed'},{'check':'tls_certificate_metadata','status':'failed'}]),C)
  self.assertEqual(m['summary']['kind'],'partial_no_findings')
 def test_no_data(self):
  m=build(scan(status='failed',checks=[]),C)
  self.assertEqual(m['summary']['kind'],'no_usable_data')
 def test_failed_tls_not_healthy(self):
  m=build(scan(tls_metadata={'status':'error','verified':False,'error_code':'invalid_url'}),C)
  self.assertEqual(m['coverage']['status'],'partial')
  self.assertEqual(m['coverage']['checks'][-1]['status'],'failed')
 def test_dedup_source_id(self):
  a=alert(id='1');m=build(scan([a,a]),C)
  self.assertEqual(m['summary']['original_alert_count'],2);self.assertEqual(m['summary']['instance_count'],1)
 def test_dedup_evidence_and_cookie(self):
  m=build(scan([alert('cookie_secure',param='one',evidence='one=abc'),alert('cookie_secure',param='two',evidence='two=abc')]),C)
  self.assertEqual(m['summary']['instance_count'],2);self.assertEqual(len(m['findings'][0]['variants']),2)
 def test_variants_same_csp_area(self):
  m=build(scan([alert(k) for k in ('csp_wildcard','csp_script_inline','csp_style_inline','csp_no_fallback')]),C)
  self.assertEqual(len(m['findings']),1);self.assertEqual(len(m['findings'][0]['variants']),4)
 def test_stable_order(self):
  aa=[alert('csp_missing'),alert('cookie_secure'),alert('php_known',risk='High')]
  one=build(scan(aa),C);two=build(scan(list(reversed(aa))),C)
  self.assertEqual([(g['number'],g['group']) for g in one['findings']],[(g['number'],g['group']) for g in two['findings']])
 def test_context_requires_review(self):
  a=alert('timestamp',review={'sensitive_context':True})
  self.assertEqual(variants(build(scan([a]),C))[0]['placement'],'technical')
  a['review'].update(confirmed=True,justification='Potwierdzono kontekst niepubliczny.')
  self.assertEqual(variants(build(scan([a]),C))[0]['priority'],'review')
 def test_empty_evidence_not_header_proof(self):
  m=build(scan([alert('csp_missing')]),C)
  self.assertIn('brak zapisu surowych',variants(m)[0]['instances'][0]['basis'])
  self.assertIn('Według automatycznej',variants(m)[0]['observation'])
 def test_contradictory_headers(self):
  d=scan([alert()]);d['raw_zap']['response']={'headers':{'content-security-policy':"default-src 'self'"}}
  self.assertIn('Rozbieżność',variants(build(d,C))[0]['observation'])
 def test_summary_refs_exist(self):
  m=build(scan([alert(k) for k in C.rules]),C)
  nums={g['number'] for g in m['findings']}
  self.assertTrue(all(r['number'] in nums for r in m['summary']['important_rows']))
 def test_no_network(self):
  with patch.object(socket,'socket',side_effect=AssertionError('network')):
   self.assertEqual(build(scan([alert()]),C)['summary']['instance_count'],1)
 def test_large_list(self):
  m=build(scan([alert('timestamp',id=str(i),evidence=str(i)) for i in range(2000)]),C)
  self.assertEqual(len(m['technical_observations']),1);self.assertEqual(m['summary']['instance_count'],2000)
 def test_source_unchanged(self):
  d=scan([alert()]);before=copy.deepcopy(d);build(d,C);self.assertEqual(d,before)

 def test_brief_cve_selection_requires_exact_version_and_evidence(self):
  technology={'name':'PHP','version':'8.2.4','version_status':'declared','sources':['http_headers']}
  def cve(identifier,**values):
   row={'cve_id':identifier,'product':'PHP','technology_name':'PHP','detected_version':'8.2.4',
        'match_status':'potentially_affected','confidence':'medium','backport_status':'unknown',
        'affected_range':'<=8.2.4','description':'The parse_str function can overwrite arbitrary variables.',
        'vendor_advisories':['http://bugs.php.net/bug.php?id=68665'],'cvss_score':7.5}
   row.update(values);return row
  result=brief_cve_candidates({'technologies':[technology],'cves':[
   cve('CVE-2025-1000'),cve('CVE-2025-1000'),cve('CVE-2025-1005',cvss_score=9),
   cve('CVE-2025-1006',cvss_score=8),cve('CVE-2025-1007',cvss_score=7),
   cve('CVE-2025-1001',product='WordPress',cvss_score=10),
   cve('CVE-2025-1002',backport_status='confirmed_patched',cvss_score=10),
   cve('CVE-2025-1003',confidence='low',cvss_score=10),
  ]})
  self.assertEqual([row['identifier'] for row in result['items']],
                   ['CVE-2025-1005','CVE-2025-1006','CVE-2025-1000'])
  candidate=next(row for row in result['items'] if row['identifier']=='CVE-2025-1000')
  self.assertEqual(candidate['vendor_link'],'https://bugs.php.net/bug.php?id=68665')
  self.assertEqual(candidate['confidence_label'],'średnia')
  self.assertIn('Potencjalne dopasowanie',candidate['match_status_label'])
 def test_ignored_cve_is_omitted_from_regular_and_brief_reports(self):
  technology={'name':'PHP','version':'8.2.4','version_status':'declared','sources':['http_headers']}
  common={'product':'PHP','technology_name':'PHP','detected_version':'8.2.4',
          'match_status':'potentially_affected','confidence':'medium','backport_status':'unknown',
          'affected_range':'<=8.2.4','sources':['NVD'],'references':[]}
  data=scan(technologies=[technology],cves=[
   {'cve_id':'cve-2007-3205',**common},{'cve_id':'CVE-2025-1008',**common}])
  model=build(data,C)
  candidates=json.dumps(model['cve_candidates'])
  self.assertNotIn('CVE-2007-3205',candidates)
  self.assertIn('CVE-2025-1008',candidates)
  brief=brief_cve_candidates(data)
  self.assertEqual([row['identifier'] for row in brief['items']],['CVE-2025-1008'])
 def test_brief_does_not_infer_cves_from_partial_versions(self):
  result=brief_cve_candidates({'technologies':[
   {'name':'PHP','version':'5.6','version_status':'declared','sources':['http_headers']}
  ],'cves':[{'cve_id':'CVE-2025-1000','product':'PHP','technology_name':'PHP',
   'detected_version':'5.6','match_status':'potentially_affected','confidence':'high',
   'affected_range':'all versions','cvss_score':10}]})
  self.assertEqual(result['items'],[])
  self.assertIn('PHP/5.6',result['note'])
  self.assertIn('rewizję dystrybucji',result['note'])

class PrivacyTests(unittest.TestCase):
 def test_url(self):
  v=safe_url('https://user:pass@example.org/token/SECRET42?email=person@example.com#fragment')
  for bad in ('user:','pass','SECRET42','person@','fragment'):self.assertNotIn(bad,v)
  self.assertEqual(safe_url('file:///etc/passwd'),'');self.assertEqual(safe_url('javascript:alert(1)'),'')
 def test_cookie(self):
  a=alert('cookie_secure',param='PHPSESSID',evidence='PHPSESSID=SESSION_SECRET; Path=/; HttpOnly; SameSite=Lax')
  value=json.dumps(extract(a,C.rules['cookie_secure'],'https://example.org/'))
  self.assertNotIn('SESSION_SECRET',value);self.assertIn('PHPSESSID',value);self.assertIn('HttpOnly',value)
 def test_form(self):
  a=alert('csrf_missing',evidence='<form id="ustawieniaStrony" method="post" action="/save?token=SECRET"><input name="csrf" value="SECRET"><script>alert("SECRET")</script></form>')
  value=json.dumps(extract(a,C.rules['csrf_missing'],'https://example.org/'))
  self.assertNotIn('SECRET',value);self.assertIn('ustawieniaStrony',value);self.assertIn('POST',value)
 def test_nonce(self):
  value=csp("script-src 'nonce-SECRET' https://cdn.example.org/a?token=TOKEN; style-src 'unsafe-inline'")
  self.assertNotIn('SECRET',value);self.assertNotIn('TOKEN',value);self.assertIn('script-src',value)
 def test_unknown_evidence(self):
  self.assertEqual(extract(alert(evidence='Authorization: Bearer secret'),None,'https://example.org')['text'],OMITTED)
 def test_resource(self):
  a=alert('sri_missing',evidence='<script src="https://cdn.example.org/a.js?session=SECRET"></script>')
  value=json.dumps(extract(a,C.rules['sri_missing'],'https://example.org'))
  self.assertNotIn('SECRET',value);self.assertIn('a.js',value)

class RealRegression(unittest.TestCase):
 def test_eight_saved_scans(self):
  root=Path(__file__).resolve().parents[2]/'output/batch-ad97af31d0f643e19220817fa0acd72a'
  if not root.exists():self.skipTest('Saved regression scans are not installed; synthetic cases still run')
  expected={'zuromin.info':(9,43),'baranowsandomierski.pl':(10,0),'bielskpodlaski.pl':(6,0),'bip.gminabratian.eu':(5,0),'wilczyn.pl':(11,0),'wolborz.eu':(41,0),'zaluski.pl':(71,0),'zawidz.bip.org.pl':(14,199)}
  seen=set()
  for file in root.glob('*.json'):
   d=json.loads(file.read_text())
   if d.get('status')!='completed':continue
   m=build(d,C);domain=m['metadata']['domain'];seen.add(domain)
   with self.subTest(domain=domain):
    self.assertEqual(m['summary']['original_alert_count'],expected[domain][0]);self.assertEqual(sum(g['count'] for g in m['cve_candidates']),expected[domain][1])
    self.assertEqual(m['diagnostics']['missing_mappings'],[])
    if domain=='zawidz.bip.org.pl':
     self.assertEqual(m['findings'][0]['priority'],'urgent');self.assertEqual(m['coverage']['status'],'partial')
     self.assertIn('Identyfikacja technologii HTTP',m['coverage']['incomplete']);self.assertIn('Weryfikacja danych certyfikatu TLS',m['coverage']['incomplete'])
    if domain in ('wilczyn.pl','zaluski.pl'):
     g=next(g for g in m['findings'] if g['group']=='csp');self.assertEqual(len(g['variants']),3 if domain=='wilczyn.pl' else 4)
     self.assertNotIn('csp_missing',[v['rule_key'] for v in g['variants']])
    if domain in ('wolborz.eu','zaluski.pl'):
     v=next(v for v in m['technical_observations'] if v['rule_key']=='timestamp');self.assertEqual(len(v['instances']),22 if domain=='wolborz.eu' else 61)
    if domain=='bip.gminabratian.eu':
     v=next(v for v in variants(m) if v['rule_key']=='csrf_missing');self.assertEqual(len(v['instances']),2);self.assertEqual(v['scanner_confidences'],['low'])
    if domain in ('baranowsandomierski.pl','bielskpodlaski.pl'):
     v=next(v for v in variants(m) if v['rule_key']=='sri_missing');self.assertEqual(len(v['instances']),3 if domain=='baranowsandomierski.pl' else 2)
  self.assertEqual(seen,set(expected))
if __name__=='__main__':unittest.main()
