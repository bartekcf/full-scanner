import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp,writeFile,rm,readdir} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {execFile} from 'node:child_process'
import {promisify} from 'node:util'
import {fileURLToPath} from 'node:url'
import {prepareModel,prepareBriefModel,renderPrepared,renderBriefPrepared,child} from '../pipeline.mjs'
import {documentDefinition,briefDocumentDefinition} from '../render-model.mjs'
const exec=promisify(execFile)
const root=fileURLToPath(new URL('..',import.meta.url))
const base={scan_id:'fixture-1',url:'https://example.org/',final_url:'https://example.org/',created_at:'2026-11-17T10:00:00Z',status:'completed',findings:[],checks:[{check:'single_http_get',status:'completed'}]}
const finding={id:'20020',title:'PHP Version with Known Vulnerabilities',severity:'high',confidence:'Low',evidence:'PHP/5.6.5',url:base.url}
async function pdfText(buffer){const dir=await mkdtemp(join(tmpdir(),'report-qa-'));try{const path=join(dir,'report.pdf');await writeFile(path,buffer);return (await exec('pdftotext',['-layout',path,'-'])).stdout}finally{await rm(dir,{recursive:true,force:true})}}

test('Searchable PDF, Polish characters, numbering and first-page incomplete coverage',async()=>{
 const model=await prepareModel({...base,findings:[finding],errors:['tls_metadata_invalid_url'],checks:[...base.checks,{check:'tls_certificate_metadata',status:'failed'}]})
 const pdf=await renderPrepared(model);assert.equal(pdf.subarray(0,5).toString(),'%PDF-')
 const txt=await pdfText(pdf);const pages=txt.split('\f').filter(t=>t.trim())
 assert.match(txt,/Wstępna analiza bezpieczeństwa strony/)
 assert.match(txt,/Pilna weryfikacja/);assert.match(txt,/Pewność detekcji: niska/)
 assert.match(pages[0],/Zakres analizy jest niepełny/)
 assert.ok(pages.every(t=>t.replace(/Stronoskop.*|Strona \d+ \/ \d+/g,'').trim().length>100))
 assert.doesNotMatch(txt,/\{target\}|\{date\}|undefined|\bNone\b|JSON|potwierdzona luka/)
 assert.match(txt,/U-01/)
})

test('Brief PDF keeps the summary, qualified CVE, company contact and short pagination',async()=>{
 const cve={cve_id:'CVE-2025-4242',product:'PHP',technology_name:'PHP',detected_version:'8.2.4',
  match_status:'potentially_affected',confidence:'medium',backport_status:'unknown',sources:['NVD'],
  affected_range:'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*',
  description:'The parse_str function can overwrite arbitrary variables.',
  vendor_advisories:['https://bugs.php.net/bug.php?id=68665'],cvss_score:7.5}
 const scan={...base,findings:[finding],technologies:[{
  name:'PHP',version:'8.2.4',version_status:'declared',sources:['http_headers'],version_conflict:false,
  cpe:'cpe:2.3:a:php:php:8.2.4:*:*:*:*:*:*:*',
 }],cves:[cve,{...cve,cve_id:'CVE-2025-4243',cvss_score:6.5},
  {...cve,cve_id:'CVE-2025-4244',cvss_score:5.5},
  {...cve,cve_id:'CVE-2025-4245',cvss_score:4.5}]}
 const model=await prepareBriefModel(scan)
 assert.equal(model.brief_cves.items.length,3)
 const briefText=await pdfText(await renderBriefPrepared(model))
 const pages=briefText.split('\f').filter(page=>page.trim())
 const normalized=briefText.replace(/\s+/gu,' ')
 assert.ok(pages.length<=3)
 assert.ok(pages.every(page=>page.trim().length>100))
 assert.match(normalized,/Raport przygotowany przez Codefellow Sp\. z o\.o\. przy użyciu narzędzia Codefellow Scout/)
 assert.match(normalized,/Liczba obszarów głównych ustaleń/)
 assert.match(normalized,/CVE-2025-4242.*PHP 8\.2\.4/)
 assert.match(normalized,/Potencjalne dopasowanie.*do weryfikacji/)
 assert.match(normalized,/Informacja producenta/)
 assert.match(normalized,/kontakt@codefellow\.pl/)
 assert.match(normalized,/\+48 795 309 804/)
 assert.match(normalized,/Raport przedstawia najważniejsze obserwacje z pasywnej analizy/)
 assert.match(normalized,/Codefellow Sp\. z o\.o\./)
 assert.doesNotMatch(briefText,/Stronoskop|Nagłówki HTTP|Lista narzędzi|Pozostałe obserwacje/)
 const cvePage=pages.find(page=>page.includes('Najważniejsze CVE'))
 assert.ok(cvePage)
 assert.match(cvePage,/CVE-2025-4242/)
 assert.match(normalized,/Zakres i kontakt/)
 assert.equal(briefDocumentDefinition(model).info.author,'Codefellow Sp. z o.o.')
 assert.equal(documentDefinition(model).info.author,'Stronoskop')
 const fullText=await pdfText(await renderPrepared(await prepareModel(scan)))
 assert.match(fullText,/Stronoskop/)
 assert.doesNotMatch(fullText,/Codefellow Scout/)
})

test('Brief omits the CVE section when no reliable match exists',async()=>{
 const model=await prepareBriefModel({...base,cves:[]})
 const briefText=await pdfText(await renderBriefPrepared(model))
 const pages=briefText.split('\f').filter(page=>page.trim())
 assert.ok(pages.length<=2)
 assert.doesNotMatch(briefText,/Najważniejsze CVE|02 \/ NAJWAŻNIEJSZE CVE/)
 assert.match(briefText,/Zakres i kontakt/)
})

test('Summary heading and findings table stay together on page',async()=>{
 const url=base.url
 const definitions=[
  ['10038','10038-1','Content Security Policy (CSP) Header Not Set'],
  ['10020','10020-1','Missing Anti-clickjacking Header'],
  ['90003','90003','Sub Resource Integrity Attribute Missing'],
  ['10035','10035-1','Strict-Transport-Security Header Not Set'],
 ]
 const alerts=definitions.map(([pluginId,alertRef,name])=>({pluginId,alertRef,name,risk:'Medium',confidence:'Low',url,evidence:''}))
 const model=await prepareModel({...base,findings:[],raw_zap:{alerts}})
 const pages=(await pdfText(await renderPrepared(model))).split('\f').filter(page=>page.trim())
 const summaryPage=pages.find(page=>/^\s*Najważniejsze ustalenia\s*$/mu.test(page))
 assert.ok(summaryPage)
 const normalized=summaryPage.replace(/\s+/gu,' ')
for(const text of [
  'Brak nagłówka polityki bezpieczeństwa',
  'clickjackingiem',
  'integralności zewnętrznych',
  'Brak deklaracji HSTS',
 ])assert.ok(normalized.includes(text),`Summary table row missing from page: ${text}`)
})


test('Sandbox rejects network and arbitrary filesystem reads',async()=>{
 const script=`import {restrictRendererIO} from './renderer-sandbox.mjs'; import fs from 'node:fs'; import http from 'node:http'; import net from 'node:net'; import dns from 'node:dns'; restrictRendererIO(); let blocked=0; for (const f of [()=>http.get('http://127.0.0.1/'),()=>net.connect(80,'127.0.0.1'),()=>dns.lookup('example.org'),()=>fetch('https://example.org'),()=>fs.readFileSync('/etc/passwd')]){try{f()}catch{blocked++}}; console.log(blocked)`
 const result=await child(process.execPath,['--input-type=module','-e',script],'')
 assert.equal(result.toString().trim(),'5')
})

test('Untrusted evidence never becomes markup, images, links or secrets',async()=>{
 const scan={...base,findings:[{...finding,id:'9999',title:'Unknown rule',evidence:'<img src="http://127.0.0.1/private"><script>SECRET</script> Authorization: Bearer SECRET'}]}
 const model=await prepareModel(scan)
 const clean=await prepareModel({...scan,findings:[{...scan.findings[0],evidence:''}]})
 const inspect=model=>{
  const resources=[]
  const json=JSON.stringify(documentDefinition(model),(key,value)=>{
   if(key==='link'||key==='image'||key==='svg')resources.push([key,value])
   return value
  })
  return {resources,json}
 }
 const {resources,json}=inspect(model)
 assert.deepEqual(resources,inspect(clean).resources)
 assert.doesNotMatch(json,/SECRET|127\.0\.0\.1|<(?:img|script)\b/)
 const txt=await pdfText(await renderPrepared(model))
 assert.doesNotMatch(txt,/SECRET|127\.0\.0\.1/)
})

test('Long evidence and many variants wrap without dropping significant findings',async()=>{
 const findings=Array.from({length:40},(_,i)=>({...finding,id:String(9000+i),title:'Unknown rule '+i,url:base.url+'a'.repeat(2000),evidence:'SECRET'.repeat(10000)}))
 const model=await prepareModel({...base,findings})
 assert.equal(model.findings[0].variants.length,40)
 const txt=await pdfText(await renderPrepared(model))
 for(let i=0;i<40;i++)assert.match(txt,new RegExp('Unknown rule '+i+'\\b'))
 assert.doesNotMatch(txt,/SECRET/)
})

test('CLI produces one document per scan, protects same-domain/date collisions, supports old --version',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'report-cli-'));try{
  const input=join(dir,'input'),output=join(dir,'output');await (await import('node:fs/promises')).mkdir(input)
  await writeFile(join(input,'a.json'),JSON.stringify(base))
  await writeFile(join(input,'b.json'),JSON.stringify({...base,scan_id:'fixture-2',findings:[finding]}))
  await exec(process.execPath,['generate.mjs','--input',input,'--output',output,'--version','full'],{cwd:root})
  assert.equal((await readdir(output)).filter(f=>f.endsWith('.pdf')).length,2)
  await exec(process.execPath,['generate.mjs','--input',input,'--output',output],{cwd:root})
  assert.equal((await readdir(output)).filter(f=>f.endsWith('.pdf')).length,2)
  const {stdout}=await exec(process.execPath,['generate.mjs','--input',input,'--output',output,'--brief'],{cwd:root})
  assert.match(stdout,/CVE: 0 \(brak wiarygodnych dopasowań\)/)
  const files=(await readdir(output)).filter(f=>f.endsWith('.pdf'))
  assert.equal(files.filter(f=>f.endsWith('--analiza.pdf')).length,2)
  assert.equal(files.filter(f=>f.endsWith('--analiza--brief.pdf')).length,2)
 }finally{await rm(dir,{recursive:true,force:true})}
})
