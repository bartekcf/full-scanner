"""Source adapter -> normalized observations -> catalog -> document model."""
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo
from .catalog import Catalog, identifier
from .privacy import clean, safe_url, extract, csp, OMITTED

VERSION='2.0.0'
RISK={'0':'info','1':'low','2':'medium','3':'high','4':'critical','informational':'info','information':'info','info':'info','low':'low','medium':'medium','high':'high','critical':'critical'}
CONF={'0':'false_positive','1':'low','2':'medium','3':'high','4':'confirmed','low':'low','medium':'medium','high':'high','confirmed':'confirmed','false positive':'false_positive'}
LABELS={'single_http_get':'Pobranie odpowiedzi HTTP','technology_fingerprinting':'Identyfikacja technologii','owasp_zap_passive':'Analiza pasywna OWASP ZAP','projectdiscovery_httpx':'Identyfikacja HTTP (httpx)','bounded_http_fingerprint':'Identyfikacja technologii HTTP','cve_correlation':'Dopasowanie do bazy CVE','dns_metadata':'Metadane DNS','tls_certificate_metadata':'Weryfikacja danych certyfikatu TLS','active_testing':'Testy aktywne','content_security_policy':'Nagłówek CSP','x_content_type_options':'Nagłówek X-Content-Type-Options','clickjacking_protection':'Ochrona przed osadzaniem','strict_transport_security':'Nagłówek HSTS'}
HEADERS={'csp_missing':'content-security-policy','csp_obsolete':'x-content-security-policy','csp_report_only':'content-security-policy-report-only','nosniff_missing':'x-content-type-options','hsts_missing':'strict-transport-security','frame_missing':'x-frame-options','server_version':'server','powered_by':'x-powered-by'}

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,default=str).encode()).hexdigest()

def array(d,k):
    v=d.get(k)
    if v is not None and not isinstance(v,list):raise ValueError('Invalid list field: '+k)
    return v or []

def adapt(scan):
    """Prefer full raw alerts; reconcile compact observations without duplicating them."""
    raw=scan.get('raw_zap') or {}
    if not isinstance(raw,dict):raise ValueError('Invalid raw_zap')
    raws=array(raw,'alerts')
    compact=array(scan,'findings')
    if len(raws)+len(compact)>20000:raise ValueError('Too many observations')
    alerts=[]
    def normalize(a,raw_source,index):
        if not isinstance(a,dict):raise ValueError('Invalid alert')
        plugin=identifier(a.get('pluginId') if raw_source else a.get('pluginId',a.get('id')))
        return {'pluginId':plugin,'alertRef':identifier(a.get('alertRef',a.get('alert_ref'))),'name':a.get('name',a.get('alert',a.get('title',''))),
          'severity':RISK.get(str(a.get('risk',a.get('severity',a.get('riskcode','')))).lower()),'confidence':CONF.get(str(a.get('confidence','')).lower()),
          'url':a.get('url',''),'method':str(a.get('method') or '').upper(),'param':a.get('param',''),'evidence':a.get('evidence'),
          'other':a.get('other'),'element':a.get('inputVector',a.get('element')),'instance_id':identifier(a.get('id')) if raw_source else identifier(a.get('instance_id')),
          'review':a.get('review') if isinstance(a.get('review'),dict) else {},'source':('raw_zap.alerts' if raw_source else 'findings')+'['+str(index)+']'}
    for i,a in enumerate(raws):alerts.append(normalize(a,True,i))
    signatures=Counter((a['pluginId'],str(a['name']),a['url'],str(a['evidence'] or '')) for a in alerts)
    for i,a in enumerate(compact):
        n=normalize(a,False,i);sig=(n['pluginId'],str(n['name']),n['url'],str(n['evidence'] or ''))
        if signatures[sig]:signatures[sig]-=1
        else:alerts.append(n)
    return alerts,raw

def classify(rule,alert,catalog):
    p=catalog.policy
    unknown=rule is None
    item=dict(rule or p['fallback'])
    item['key']=item.get('key','unknown_'+digest([alert['alertRef'],alert['pluginId'],alert['name']])[:16])
    item['default_priority']=item.get('default_priority',item.get('priority','review'))
    item['placement']=item.get('placement','main' if alert['severity'] in ('high','critical','medium',None) else 'technical')
    if unknown:
        item['default_priority']='info' if alert['severity']=='info' else 'improve' if alert['severity']=='low' else 'review'
    priority=item['default_priority']
    review=alert['review']
    justified=review.get('confirmed') is True and isinstance(review.get('justification'),str) and bool(review['justification'].strip())
    for override in p['priority_overrides']:
        conditions=[]
        for k,v in override['when'].items():
            if k=='scanner_severity_in':conditions.append(alert['severity'] in v)
            elif k=='verification_status_not':conditions.append(item['verification_status']!=v)
            elif k=='rule_key_in':conditions.append(item['key'] in v)
            elif k=='unmapped':conditions.append(unknown==v)
            elif k=='reviewer_confirmed_sensitive_context':conditions.append((justified and review.get('sensitive_context') is True)==v)
            elif k=='reviewer_confirmed_sensitive_cookie':conditions.append((justified and review.get('sensitive_cookie') is True)==v)
        if all(conditions):
            priority=override.get('set_priority',priority)
            item['placement']=override.get('set_placement',item['placement'])
    if priority=='urgent':item['placement']='main'
    item['priority']=priority
    item['review_justification']=clean(review['justification'],400) if justified else None
    return item

def coverage(scan,raw,catalog):
    p=catalog.policy['coverage'];rows=[];errors=[]
    for c in array(scan,'checks'):
        if not isinstance(c,dict):continue
        key=str(c.get('check',''));status=c.get('status','unknown')
        status={'not_applicable':'out_of_scope','not_collected':'unknown'}.get(status,status)
        if status not in p['statuses']:status='unknown'
        note='Kontrola wykonana; wynik nie jest oceną bezpieczeństwa całej strony.' if status=='completed' else p['statuses'][status]+'.'
        if key=='active_testing':note='Bez prób wykorzystania podatności.'
        rows.append({'key':key if re.fullmatch(r'[a-z_]{1,80}',key) else 'unknown','label':p['module_labels'].get(key,LABELS.get(key,'Inna kontrola')),'status':status,'note':note})
    if type(scan.get('http_status')) is int:
        rows.insert(0,{'key':'http','label':'Odpowiedź HTTP','status':'completed','note':'Zapisany kod odpowiedzi: '+str(scan['http_status'])+'. Sam kod nie potwierdza kompletności analizy.'})
    if 'redirects' in scan:
        hops=array(scan,'redirects')
        downgrade=any(isinstance(h,dict) and h.get('https_to_http') is True for h in hops)
        rows.append({'key':'redirects','label':'Przekierowania HTTP','status':'completed' if scan.get('status')=='completed' else 'partial','note':f'Zapisane przejścia: {len(hops)}.'+(' Zapis wskazuje przejście z HTTPS na HTTP; zalecana weryfikacja.' if downgrade else '')})
    for h in array(scan,'http_checks'):
        if not isinstance(h,dict):continue
        key=h.get('check','');status=h.get('status')
        notes={'present':'Moduł odnotował obecność deklaracji; nie jest to pełna ocena jej skuteczności.','missing':'Moduł odnotował brak oczekiwanej deklaracji.','not_applicable':'Kontrola nie dotyczy analizowanej odpowiedzi.'}
        rows.append({'key':key if key in LABELS else 'unknown_header','label':LABELS.get(key,'Kontrola nagłówka'),'status':'completed' if status in ('present','missing') else 'out_of_scope' if status=='not_applicable' else 'unknown','note':notes.get(status,'Brak jednoznacznego wyniku modułu.')})
    tls=scan.get('tls_metadata')
    if isinstance(tls,dict):
        row=next((r for r in rows if r['key']=='tls_certificate_metadata'),None)
        if row is None:
            row={'key':'tls_certificate_metadata','label':LABELS['tls_certificate_metadata'],'status':'unknown','note':''};rows.append(row)
        if tls.get('status')=='ok':
            row['status']='completed'
            row['note']='Zebrano metadane TLS. Weryfikacja certyfikatu przez moduł: '+('powiodła się.' if tls.get('verified') is True else 'brak potwierdzenia poprawności.')
            if re.fullmatch(r'TLSv?1\.[0-3]',str(tls.get('tls_version',''))):row['note']+=' Protokół: '+tls['tls_version']+'.'
            for k,label in [('not_before','Ważny od'),('not_after','Ważny do')]:
                v=tls.get(k)
                if isinstance(v,str) and re.fullmatch(r'[A-Za-z0-9 :+.,/-]{1,50}',v):row['note']+=' '+label+': '+v+'.'
        elif tls.get('status')=='error':row.update(status='failed',note=p['error_labels'].get('tls_metadata_'+str(tls.get('error_code')),p['fallback_error']))
        elif tls.get('status')=='not_applicable':row.update(status='out_of_scope',note='Brak kontroli certyfikatu dla tego połączenia.')
    codes=array(scan,'errors')+([scan['error']] if scan.get('error') else [])
    for code in codes:
        errors.append({'code_hash':digest(code)[:16],'message':p['error_labels'].get(str(code),p['fallback_error'])})
    incomplete=[r['label'] for r in rows if r['status'] in ('partial','failed','unknown')]
    if errors and not incomplete:incomplete=['kontrole dodatkowe']
    has_response=isinstance(raw.get('response'),dict) and type(raw['response'].get('status')) is int
    usable=has_response or type(scan.get('http_status')) is int or bool(array(scan,'findings')) or bool(array(raw,'alerts')) or any(r['status']=='completed' and r['key']!='redirects' for r in rows)
    status='no_usable_data' if not usable else 'partial' if incomplete or scan.get('status')!='completed' else 'completed'
    return {'status':status,'checks':rows,'errors':errors,'incomplete':incomplete,'fields_present':{k:k in scan for k in ('findings','checks','errors','tls_metadata','http_checks')}}

def cve_candidates(scan):
    groups={}
    candidates=array(scan,'cves')
    if len(candidates)>20000:raise ValueError('Too many CVE candidates')
    for c in candidates:
        if not isinstance(c,dict):continue
        product=clean(c.get('product') or c.get('technology_name'),100) or 'Produkt nieokreślony'
        version=clean(c.get('detected_version'),50) or 'Brak pełnej wersji'
        key=(product,version)
        g=groups.setdefault(key,{'product':product,'version':version,'count':0,'statuses':Counter(),'sources':set(),'identifiers':set(),'references':set(),'backports':'Nie potwierdzono stanu poprawek dostawcy.'})
        g['count']+=1
        status=c.get('match_status')
        translations={'confirmed_affected_version':'Dopasowanie wersji do zakresu CVE (bez potwierdzenia podatności serwisu)','potentially_affected':'Potencjalne dopasowanie','insufficient_evidence':'Niewystarczające dane','not_affected':'Wersja poza wskazanym zakresem'}
        g['statuses'][translations.get(status,'Brak danych o dopasowaniu')]+=1
        for source in c.get('sources',[]):
            if source in ('nvd','osv','github','cisa_kev','epss','NVD','OSV','GitHub'):g['sources'].add(source)
            elif safe_url(source):g['sources'].add(safe_url(source))
        if re.fullmatch(r'CVE-\d{4}-\d{4,}',str(c.get('cve_id'))):g['identifiers'].add(c['cve_id'])
        for url in c.get('references',[]):
            if safe_url(url):g['references'].add(safe_url(url))
    result=[]
    for _,g in sorted(groups.items()):
        for k in ('sources','identifiers','references'):g[k]=sorted(g[k])
        g['statuses']=dict(g['statuses']);result.append(g)
    return result

def _brief_product(value):
    name=clean(value,100).casefold()
    aliases={'apache':'apachehttpserver','httpd':'apachehttpserver'}
    key=re.sub(r'[\W_]+','',name)
    return aliases.get(key,key),clean(value,100)

def _brief_version(value):
    return isinstance(value,str) and re.fullmatch(r'\d+(?:\.\d+){2,5}',value.strip()) is not None

def _brief_vendor_link(record,product):
    values=[]
    for field in ('vendor_advisories','references'):
        field_values=record.get(field)
        if isinstance(field_values,list):values.extend(field_values[:50])
    for value in values[:100]:
        if not isinstance(value,str) or len(value)>200:continue
        if product=='php':
            if match:=re.fullmatch(r'https?://(?:www\.)?php\.net/(ChangeLog-[578]\.php)(?:#([0-9]+\.[0-9]+\.[0-9]+))?',value,re.I):
                return 'https://www.php.net/'+match[1]+('#'+match[2] if match[2] else '')
            if match:=re.fullmatch(r'https?://(?:www\.)?bugs\.php\.net/bug\.php\?id=([0-9]{1,8})',value,re.I):
                return 'https://bugs.php.net/bug.php?id='+match[1]
            if match:=re.fullmatch(r'https://github\.com/php/php-src/security/advisories/(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})',value,re.I):
                return 'https://github.com/php/php-src/security/advisories/'+match[1].lower()
        if product=='apachehttpserver':
            if match:=re.fullmatch(r'https?://httpd\.apache\.org/security/vulnerabilities_(22|24)\.html#(CVE-\d{4}-\d{4,12})',value,re.I):
                return f'https://httpd.apache.org/security/vulnerabilities_{match[1]}.html#{match[2].upper()}'
    return ''

def _brief_cve_impact(description):
    text=clean(description,1500).casefold()
    if re.search(r'\bparse[_ ]str\b|overwrite arbitrary variables',text):
        return 'Jeśli aplikacja wywołuje parse_str bez drugiego argumentu, dane wejściowe mogą nadpisać zmienne; znaczenie zależy od użycia tej funkcji w serwisie.'
    if re.search(r'remote code execution|execute arbitrary code|arbitrary code execution',text):
        return 'W spełnionych warunkach podatność może umożliwić wykonanie kodu na serwerze i naruszyć działanie serwisu.'
    if re.search(r'sql injection|sql commands?',text):
        return 'W spełnionych warunkach podatność może umożliwić odczyt lub zmianę danych obsługiwanych przez serwis.'
    if re.search(r'cross.site scripting|\bxss\b',text):
        return 'W spełnionych warunkach podatność może umożliwić uruchomienie skryptu w przeglądarce użytkownika serwisu.'
    if re.search(r'denial.of.service|\bdos\b|resource exhaustion',text):
        return 'W spełnionych warunkach podatność może zakłócić dostępność serwisu.'
    if re.search(r'authentication bypass|authorization bypass|privilege escalation',text):
        return 'W spełnionych warunkach podatność może pozwolić ominąć kontrolę dostępu lub uzyskać nieuprawnione możliwości.'
    if re.search(r'information disclosure|information leak|arbitrary file read|read arbitrary files',text):
        return 'W spełnionych warunkach podatność może ujawnić dane lub pliki dostępne dla komponentu serwera.'
    if re.search(r'server.side request forgery|\bssrf\b',text):
        return 'W spełnionych warunkach podatność może pozwolić wymusić żądania z serwera do innych zasobów.'
    if re.search(r'path traversal|directory traversal|arbitrary file write|write arbitrary files',text):
        return 'W spełnionych warunkach podatność może umożliwić dostęp do plików poza zamierzonym zakresem.'
    return 'Opis wskazuje na problem w komponencie; wpływ na serwis zależy od warunków w komunikacie producenta i konfiguracji pakietu.'

def brief_cve_candidates(scan):
    """Choose only CVEs tied to a reliable, exact technology version and scanner match."""
    technologies={}
    for technology in array(scan,'technologies'):
        if not isinstance(technology,dict):continue
        key,product=_brief_product(technology.get('name'))
        if not key:continue
        entry=technologies.setdefault(key,{'product':product,'versions':set(),'conflict':False})
        entry['conflict']|=bool(technology.get('version_conflict'))
        source_values=technology.get('sources')
        sources=[source for source in source_values if isinstance(source,str)] if isinstance(source_values,list) else []
        status=technology.get('version_status')
        reliable=bool(sources and (status in ('declared','verified') or
                                   (status=='fingerprinted' and len(set(sources))>1)))
        version=technology.get('version')
        if reliable and _brief_version(version):entry['versions'].add(version.strip())

    candidates=[]
    weak_versions,conflicts=set(),set()
    cve_rows=array(scan,'cves')
    for record in cve_rows:
        if not isinstance(record,dict):continue
        match_status=record.get('match_status')
        if match_status not in ('confirmed_affected_version','potentially_affected'):continue
        identifier=record.get('cve_id')
        if not isinstance(identifier,str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}',identifier,re.I):continue
        technology_name=record.get('technology_name')
        source_product=record.get('product')
        key,product=_brief_product(technology_name or source_product)
        source_key,_=_brief_product(source_product)
        if technology_name and source_product and source_key and source_key!=key:
            conflicts.add(product or clean(source_product,100))
            continue
        technology=technologies.get(key)
        detected=record.get('detected_version')
        if not technology or not technology['versions']:
            weak_versions.add(f'{product}/{clean(detected,50) or "brak wersji"}')
            continue
        if technology['conflict'] or len(technology['versions'])!=1:
            conflicts.add(product)
            continue
        version=next(iter(technology['versions']))
        if not _brief_version(version) or detected!=version:
            weak_versions.add(f'{product}/{clean(detected,50) or version}')
            continue

        confidence=record.get('confidence')
        if confidence not in ('high','medium'):continue
        backport=record.get('backport_status') or 'unknown'
        if backport in ('confirmed','patched','backported','confirmed_patched',
                        'confirmed_backport','backport_confirmed'):continue
        if not record.get('affected_range') and not record.get('applicability'):continue

        score=record.get('cvss_score')
        if isinstance(score,bool) or not isinstance(score,(int,float)) or not 0<=score<=10:score=None
        candidates.append({
            'identifier':identifier.upper(),
            'product':product,
            'version':version,
            'match_status_label':('Potencjalne dopasowanie — do weryfikacji'
                                  if match_status=='potentially_affected'
                                  else 'Wersja pasuje do zakresu'),
            'confidence_label':{'high':'wysoka','medium':'średnia'}[confidence],
            'backport_status_label':('brak poprawki zapisany'
                                     if backport in ('not_patched','confirmed_not_patched','not_backported')
                                     else 'nieustalony'),
            'explanation':_brief_cve_impact(record.get('description')),
            'recommendation':('Porównać pełne wydanie pakietu i poprawki dostawcy z komunikatem producenta; '
                              'zastosować wskazane wydanie naprawione, jeśli zakres potwierdzi dopasowanie.'),
            'vendor_link':_brief_vendor_link(record,key),
            'cvss_score':score,
            'cisa_kev':record.get('cisa_kev') is True,
            'match_rank':0 if match_status=='confirmed_affected_version' else 1,
            'confidence_rank':0 if confidence=='high' else 1,
            'backport_rank':0 if backport in ('not_patched','confirmed_not_patched','not_backported') else 1,
        })

    candidates.sort(key=lambda item:(item['match_rank'],item['confidence_rank'],item['backport_rank'],
                                     not item['cisa_kev'],
                                     -(item['cvss_score'] if item['cvss_score'] is not None else -1),
                                     item['identifier']))
    selected,seen=[],set()
    for candidate in candidates:
        if candidate['identifier'] in seen:continue
        seen.add(candidate['identifier'])
        selected.append({key:value for key,value in candidate.items()
                         if key not in ('match_rank','confidence_rank','backport_rank')})
        if len(selected)==3:break

    if selected:
        note=('Dopasowanie zakresu wersji nie potwierdza podatności serwisu; status poprawek dostawcy '
              'i warunki występowania należy potwierdzić u administratora.')
    elif not cve_rows:
        note='Zapisany JSON nie zawiera kandydatów CVE.'
    elif weak_versions:
        note=(f'Zapisane dopasowania dla {", ".join(sorted(weak_versions)[:3])} są zbyt ogólne, aby wskazać konkretne CVE. '
              'Administrator powinien ustalić dokładne wydanie pakietu, w tym rewizję dystrybucji, '
              'oraz stan poprawek lub backportów dostawcy.')
    elif conflicts:
        note=(f'Zapis zawiera sprzeczne wersje {", ".join(sorted(conflicts)[:3])}; administrator powinien ustalić '
              'dokładne wydanie pakietu i stan poprawek dostawcy przed oceną CVE.')
    else:
        note=('Zapis nie pozwala potwierdzić wiarygodnego dopasowania CVE do rozpoznanej technologii i jej wersji. '
              'Administrator powinien porównać pełne wydanie pakietu oraz poprawki dostawcy z komunikatem producenta.')
    return {'items':selected,'note':note}

def build(scan,catalog=None):
    if not isinstance(scan,dict):raise ValueError('Scan must be object')
    catalog=catalog or Catalog();policy=catalog.policy;copy=catalog.copy
    alerts,raw=adapt(scan)
    target=safe_url(scan.get('url'));final=safe_url(scan.get('final_url')) or target
    if not target:raise ValueError('Missing valid target URL')
    from urllib.parse import urlsplit
    date=None
    if isinstance(scan.get('created_at'),str):
        try:
            dt=datetime.fromisoformat(scan['created_at'].replace('Z','+00:00'))
            if dt.tzinfo:date=dt.astimezone(ZoneInfo('Europe/Warsaw')).isoformat()
        except ValueError:pass
    cov=coverage(scan,raw,catalog)
    buckets={};missing=[];seen=set()
    headers=raw.get('response',{}).get('headers') if isinstance(raw.get('response'),dict) else None
    headers={str(k).lower():v for k,v in headers.items()} if isinstance(headers,dict) else None
    for a in alerts:
        rule,reason=catalog.match(a)
        if not rule:missing.append({'plugin_id':a['pluginId'] if re.fullmatch(r'\d+(?:-\d+)?',a['pluginId']) else None,'alert_ref':a['alertRef'] if re.fullmatch(r'\d+(?:-\d+)?',a['alertRef']) else None,'name':clean(a['name']), 'reason':reason,'source':a['source']})
        item=classify(rule,a,catalog)
        safe=extract(a,rule,scan.get('final_url') or scan.get('url'))
        source_identity=[a['pluginId'],a['alertRef'],a['instance_id']] if a['instance_id'] else [a['alertRef'] or item['key'],a['url'],a['method'],a['param'],a['element'],a['evidence']]
        instance_key=digest(source_identity)
        if instance_key in seen:continue
        seen.add(instance_key)
        # Cookie identity and product/version are retained within each area; no URL-only merge.
        context=safe['identity'] if item['group'] in ('cookies','server_technology') else {}
        key=digest([item['key'],context,item['priority'],item['placement']])
        basis='Automatyczna obserwacja ZAP; brak zapisu surowych nagłówków w danych raportu.'
        observation=item['observation']
        if headers is not None and a['url']==(scan.get('final_url') or scan.get('url')):
            basis='Automatyczna obserwacja ZAP; zapisano nagłówki analizowanej odpowiedzi HTTP.'
            header=HEADERS.get(item['key'])
            if header:
                present=header in headers
                basis+=' Nagłówek '+header+': '+('obecny.' if present else 'nieobecny w zapisanej odpowiedzi.')
                if item['key']=='csp_missing' and present:
                    observation='ZAP zgłosił brak CSP, lecz zapisane nagłówki zawierają tę deklarację. Rozbieżność wymaga sprawdzenia kontekstu odpowiedzi.'
                if item['key'].startswith('csp_') and present:
                    safe['text']=csp(headers[header],item['key']) or safe['text']
        elif item['key'].endswith('missing'):
            observation='Według automatycznej obserwacji ZAP: '+observation[0].lower()+observation[1:]
        g=buckets.setdefault(key,{'stable_key':key,'rule_key':item['key'],'group':item['group'],'title':item['title'],'priority':item['priority'],'placement':item['placement'],
            'verification_status':item['verification_status'],'observation':observation,'impact':item['impact'],'recommendation':item['recommendation'],'verification':item['verification'],
            'limitations':item.get('limitations',''),'review_justification':item.get('review_justification'),'instances':[],'source_refs':[],'references':item.get('references',[]),'scanner_risks':set(),'scanner_confidences':set()})
        g['scanner_risks'].add(a['severity']);g['scanner_confidences'].add(a['confidence'])
        g['source_refs'].append(a['source'])
        g['instances'].append({'stable_key':instance_key,'url':safe['url'],'evidence':safe['text'],'identity':safe['identity'],'resource_urls':safe['resource_urls'],'basis':basis,
            'method':a['method'] if a['method'] in ('GET','POST','HEAD','PUT','DELETE','OPTIONS','PATCH') else None,
            'original_name':clean(a['name']),'plugin_id':a['pluginId'] if re.fullmatch(r'\d+(?:-\d+)?',a['pluginId']) else None,'alert_ref':a['alertRef'] if re.fullmatch(r'\d+(?:-\d+)?',a['alertRef']) else None})
    values=list(buckets.values())
    for g in values:
        g['scanner_risks']=sorted(g['scanner_risks'],key=lambda x:str(x));g['scanner_confidences']=sorted(g['scanner_confidences'],key=lambda x:str(x))
        g['instances'].sort(key=lambda x:x['stable_key'])
    order=lambda g:(policy['priorities'][g['priority']]['rank'],policy['groups'][g['group']]['order'],g['stable_key'])
    values.sort(key=order)
    main=[g for g in values if g['placement']=='main'];technical=[g for g in values if g['placement']=='technical']
    # One U-number per area, with independently preserved variant records.
    areas={}
    for f in main:
        group=areas.setdefault(f['group'],{'group':f['group'],'title':policy['groups'][f['group']]['title'],'priority':f['priority'],'stable_key':f['group'],'variants':[]})
        group['variants'].append(f)
    findings=sorted(areas.values(),key=order)
    for i,g in enumerate(findings,1):g['number']=f'U-{i:02}'
    kind=findings[0]['priority'] if findings else 'info_only' if technical else 'no_findings'
    if cov['status']=='no_usable_data':kind='no_usable_data'
    elif cov['status']=='partial' and not findings:kind='partial_no_findings'
    template=copy['report']['summaries'].get(kind)
    summary_text=(template.format(priority_items=', '.join(g['variants'][0]['title'] for g in findings[:3]),areas=', '.join(g['title'] for g in findings[:3])) if template else 'W częściowo wykonanej analizie nie odnotowano ustaleń wymagających działania. Brak wyników pozostałych kontroli uniemożliwia ocenę ich zakresu.')
    warnings=[]
    if not any(copy['brand'].get(key) for key in ('email', 'website', 'phone')):
        warnings.append('Brak danych kontaktowych wykonawcy. Uzupełnić konfigurację przed dystrybucją.')
    if not date:warnings.append('Brak daty skanu ze strefą czasową; raport nie zastępuje jej datą generowania.')
    if missing:warnings.append(f'Reguły wymagające rozszerzenia katalogu: {len(missing)} obserwacji; szczegóły w lokalnym logu.')
    cves=cve_candidates(scan)
    # Exact resource association only, without merging their independent meanings.
    resource_index=defaultdict(set)
    for g in values:
        for inst in g['instances']:
            for url in inst['resource_urls']:resource_index[url].add(g['rule_key'])
    for g in values:
        g['related_resource_rules']=sorted({r for inst in g['instances'] for u in inst['resource_urls'] for r in resource_index[u] if r!=g['rule_key']})
    return {'schema_version':1,'metadata':{'target':target,'final_url':final,'domain':urlsplit(final).hostname,'scanned_at':date,'timezone':'Europe/Warsaw','report_id':digest(scan.get('scan_id') or scan)[:16],'generator_version':VERSION,'method':copy['report']['method']},
      'coverage':cov,'findings':findings,'technical_observations':technical,'cve_candidates':cves,
      'summary':{'kind':kind,'text':summary_text,'action':copy['report']['actions'].get(kind,copy['report']['actions']['no_usable_data']), 'original_alert_count':len(alerts),'compact_alert_count':len(array(scan,'findings')) if 'findings' in scan else None,'instance_count':len(seen),'group_count':len(findings),'technical_group_count':len(technical),'important_rows':[{'number':g['number'],'area':g['title'],'title':g['variants'][0]['title'],'recommendation':{
      'csp':'Zweryfikować politykę CSP.', 'browser_headers':'Zweryfikować konfigurację nagłówków.',
      'forms':'Sprawdzić ochronę formularzy.', 'cookies':'Dobrać atrybuty do funkcji cookies.',
      'external_resources':'Zweryfikować źródła i integralność zasobów.', 'transport':'Zweryfikować konfigurację HTTPS.',
      'server_technology':'Potwierdzić wersje i stan poprawek.'}.get(g['group'],'Zweryfikować wskazaną obserwację.')} for g in findings[:4]]},
      'copy':copy,'policy':{'priorities':policy['priorities'],'groups':policy['groups'],'coverage':policy['coverage']},'diagnostics':{'warnings':warnings,'missing_mappings':missing,'source_digest':digest(scan)}}
