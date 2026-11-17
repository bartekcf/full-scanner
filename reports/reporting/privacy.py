"""Allowlisted extraction. Raw evidence never reaches the presentation model."""
import re
import unicodedata
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit, unquote, quote

OMITTED='Dostępny zapis nie pozwala na bezpieczne przytoczenie surowego dowodu.'

def clean(value, limit=180):
    if not isinstance(value,(str,int,float)): return ''
    text=' '.join(unicodedata.normalize('NFKC',str(value)).split())
    text=''.join(c for c in text if unicodedata.category(c)[0]!='C')
    text=re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '[dane usunięte]',text)
    text=re.sub(r'(?i)(authorization|cookie|password|passwd|token|secret|session|csrf|nonce)\s*[:=]\s*\S+',r'\1=[usunięto]',text)
    text=re.sub(r'\b\d{9,}\b','[dane usunięte]',text)
    text=re.sub(r'\b[A-Za-z0-9_+/=-]{32,}\b','[dane usunięte]',text)
    if '<' in text or '>' in text: return '[fragment kodu pominięty]'
    return text if len(text)<=limit else text[:limit]+'… [skrócono]'

def token(value):
    v=str(value or '')
    return v if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.:-]{0,63}',v) else ''

def safe_url(value, base=None):
    if not isinstance(value,str) or len(value)>8192:return ''
    try:
        from urllib.parse import urljoin
        u=urlsplit(urljoin(base,value) if base else value)
        if u.scheme not in ('http','https') or not u.hostname:return ''
        host=u.hostname.encode('idna').decode('ascii')
        if not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}',host):return ''
        parts=[]
        hide_next=False
        for part in u.path.split('/'):
            decoded=unquote(part)
            sensitive=hide_next or '@' in decoded or re.search(r'(?i)(token|secret|session|password|csrf|nonce)[=:]',decoded) or re.search(r'[A-Za-z0-9_-]{24,}|\d{9,}',decoded)
            hide_next=bool(re.fullmatch(r'(?i)(token|secret|session|password|csrf|nonce|users?|people|email)',decoded))
            parts.append('[usunięto]' if sensitive else quote(decoded,safe='-._~,;:'))
        path='/'.join(parts)
        # Parameter names can also contain personal data; redact the entire query.
        result=urlunsplit((u.scheme,host+((':'+str(u.port)) if u.port else ''),path,'[parametry usunięte]' if u.query else '', ''))
        return result if len(result)<=400 else result[:400]+'… [adres skrócono]'
    except (ValueError,UnicodeError): return ''

class Elements(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base,self.forms,self.resources=base,[],[]
    def handle_starttag(self, tag, attrs):
        a=dict(attrs)
        if tag=='form':
            item={}
            if token(a.get('id')):item['id']=token(a['id'])
            if str(a.get('method','')).upper() in ('GET','POST'): item['method']=a['method'].upper()
            if a.get('action') and safe_url(a['action'],self.base):item['action']=safe_url(a['action'],self.base)
            self.forms.append(item)
        if tag in ('script','link'):
            url=safe_url(a.get('src') or a.get('href'),self.base)
            if url:self.resources.append({'type':tag,'url':url})

CSP_DIRECTIVES={'default-src','script-src','style-src','img-src','connect-src','font-src','object-src','media-src','frame-src','child-src','worker-src','manifest-src','frame-ancestors','base-uri','form-action','script-src-elem','script-src-attr','style-src-elem','style-src-attr','upgrade-insecure-requests','block-all-mixed-content','sandbox'}

def csp(value, rule_key=None):
    found=[]
    for segment in str(value or '').split(';'):
        words=segment.strip().split()
        if not words:continue
        directive=words[0].lower().removeprefix('content-security-policy:')
        if directive not in CSP_DIRECTIVES:continue
        if rule_key=='csp_script_inline' and directive not in ('script-src','script-src-elem','script-src-attr'):continue
        if rule_key=='csp_style_inline' and directive not in ('style-src','style-src-elem','style-src-attr'):continue
        if rule_key=='csp_eval' and directive not in ('script-src','script-src-elem'):continue
        if rule_key=='csp_wildcard' and not any('*' in w for w in words[1:]):continue
        out=[]
        for w in words[1:]:
            if w.startswith(("'nonce-","'sha256-","'sha384-","'sha512-")):out.append("'[wartość usunięta]'")
            elif w in ("'self'","'none'","'unsafe-inline'","'unsafe-eval'","'strict-dynamic'","'report-sample'",'*','https:','http:','data:','blob:'):out.append(w)
            elif safe_url(w):out.append(safe_url(w))
            elif re.fullmatch(r'(?:\*\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?',w):out.append(w)
            else:out.append('[wartość pominięta]')
        if len(out)>8:out=out[:8]+[f'[{len(out)-8} źródeł pominięto]']
        found.append(directive+' '+' '.join(out))
    return '; '.join(found)[:1200] + ('… [skrócono]' if sum(len(str(x)) for x in found)>1200 else '')

def extract(alert, rule, final_url):
    key=rule.get('key','') if rule else ''
    raw=str(alert.get('evidence') or '')[:200000]
    url=safe_url(alert.get('url'))
    result={'url':url,'text':OMITTED,'identity':{},'resource_urls':[]}
    if key.startswith('cookie_') or key=='session_identified':
        cookie=token(alert.get('param'))
        m=re.search(r'(?:^|\n|Set-Cookie:\s*)([A-Za-z_][A-Za-z0-9_.:-]{0,63})\s*=',raw,re.I)
        if not cookie and m:cookie=m.group(1)
        if cookie:
            domain=re.search(r'(?i)(?:^|;)\s*domain=([.a-zA-Z0-9-]+)(?:;|$)',raw)
            path=re.search(r'(?i)(?:^|;)\s*path=([^;\s]+)',raw)
            attrs=[]
            for flag in ('HttpOnly','Secure'):
                if re.search(r'(?i)(?:^|;)\s*'+flag+r'\s*(?:;|$)',raw):attrs.append(flag)
            same=re.search(r'(?i)(?:^|;)\s*SameSite=(Lax|Strict|None)(?:;|$)',raw)
            if same:attrs.append('SameSite='+same.group(1))
            result['identity']={'cookie_name':cookie,'domain':domain.group(1) if domain else None,'path':safe_url(path.group(1),final_url) if path else None}
            result['text']='Cookie: '+cookie+' (wartość pominięta).'+(' Zapisane atrybuty: '+', '.join(attrs)+'.' if attrs else '')
            if domain:result['text']+=' Domena: '+domain.group(1)+'.'
            if path:result['text']+=' Ścieżka: '+safe_url(path.group(1),final_url)+'.'
        return result
    if key in ('csrf_missing','sri_missing','external_js'):
        parser=Elements(final_url)
        try:parser.feed(raw)
        except Exception:pass
        if key=='csrf_missing' and parser.forms:
            result['identity']={'forms':parser.forms}
            result['text']='; '.join('Formularz: '+', '.join(k+'='+v for k,v in f.items()) if f else 'Formularz bez zapisanych bezpiecznych atrybutów.' for f in parser.forms[:3])
        elif key!='csrf_missing':
            resources=parser.resources
            if not resources and safe_url(raw):resources=[{'type':'zasób','url':safe_url(raw)}]
            result['resource_urls']=[r['url'] for r in resources]
            result['identity']={'resources':resources}
            if resources:result['text']='; '.join(r['type']+': '+r['url'] for r in resources[:3])
        return result
    if key.startswith('csp_'):
        if key=='csp_no_fallback':
            context=raw+' '+str(alert.get('other') or '')
            directives=sorted(set(re.findall(r'\b(?:'+ '|'.join(sorted(CSP_DIRECTIVES,key=len,reverse=True))+r')\b',context)))
            value='Dyrektywy wymienione w szczegółach alertu: '+', '.join(directives) if directives else ''
        else:value=csp(raw,key)
        if value:result['text']=value
        return result
    if key in ('php_known','php_possible','server_version','powered_by'):
        versions=re.findall(r'\b(PHP|Apache|nginx|Microsoft-IIS|OpenSSL|ASP\.NET)[/ ]([0-9]+(?:\.[0-9A-Za-z-]+){0,5})',raw,re.I)
        if versions:
            result['text']='; '.join(product+'/'+version for product,version in versions[:8])
            result['identity']={'versions':versions}
        return result
    if key in ('frame_missing','nosniff_missing','hsts_missing','modern_app','timestamp','cache_review'):
        result['text']='Dowód ma postać obserwacji reguły; nie przytaczano surowej treści odpowiedzi.'
    return result
