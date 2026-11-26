import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp,writeFile,readFile,rm,readdir} from 'node:fs/promises'
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
 }],cves:[{...cve,cve_id:'CVE-2007-3205',cvss_score:10},cve,{...cve,cve_id:'CVE-2025-4243',cvss_score:6.5},
  {...cve,cve_id:'CVE-2025-4244',cvss_score:5.5},
  {...cve,cve_id:'CVE-2025-4245',cvss_score:4.5}]}
 const model=await prepareBriefModel(scan)
 assert.equal(model.brief_cves.items.length,3)
 const briefText=await pdfText(await renderBriefPrepared(model))
 const whiteText=await pdfText(await renderBriefPrepared(model,true))
 const whitePages=whiteText.split('\f').filter(page=>page.trim())
 const whiteNormalized=whiteText.replace(/\s+/gu,' ')
 const pages=briefText.split('\f').filter(page=>page.trim())
 const normalized=briefText.replace(/\s+/gu,' ')
 assert.doesNotMatch(normalized,/CVE-2007-3205/)
 assert.doesNotMatch(whiteNormalized,/CVE-2007-3205/)
 assert.ok(whitePages.length>=3&&whitePages.length<=4)
 assert.ok(whitePages.every(page=>page.trim().length>100))
 assert.match(whitePages[0],/example\.org/)
 assert.match(whitePages[0],/Priorytety weryfikacji/)
 assert.match(whitePages[0],/Obszary ustaleń/)
 assert.match(whitePages[0],/1 obszar/)
 for(const id of ['CVE-2025-4242','CVE-2025-4243','CVE-2025-4244']){
  assert.match(normalized,new RegExp(id))
  assert.match(whiteNormalized,new RegExp(id))
 }
 for(const recommendation of new Set(model.brief_cves.items.map(item=>item.recommendation))){
  assert.ok(normalized.includes(recommendation))
  assert.ok(whiteNormalized.includes(recommendation))
 }
 assert.match(whiteNormalized,/Źródło producenta/)
 assert.match(whiteNormalized,/WSPÓLNE ZALECENIE/)
 assert.doesNotMatch(whiteText,/Stronoskop/)
 assert.match(whitePages.at(-1),/Zakres i kontakt/)
 assert.match(whitePages.at(-1),/kontakt@codefellow\.pl/)
 assert.equal(pages.length,3)
 assert.ok(pages.every(page=>page.trim().length>100))
 assert.match(normalized,/Raport przygotowany przez Codefellow Sp\. z o\.o\. przy użyciu narzędzia Codefellow Scout/)
 assert.match(normalized,/Liczba obszarów głównych ustaleń/)
 assert.match(normalized,/PHP · zaobserwowana wersja 8\.2\.4/)
 for(const id of ['CVE-2025-4242','CVE-2025-4243','CVE-2025-4244'])assert.match(normalized,new RegExp(id))
 assert.equal((briefText.match(/Zalecenie:/gu)||[]).length,1)
 assert.match(normalized,/Potencjalne dopasowanie.*do weryfikacji/)
 assert.match(normalized,/Informacja producenta — CVE-2025-4242/)
 assert.match(normalized,/kontakt@codefellow\.pl/)
 assert.match(normalized,/\+48 795 309 804/)
 assert.match(normalized,/Dokument przedstawia wybrane, najważniejsze obserwacje z pasywnej analizy/)
 assert.match(normalized,/Codefellow Sp\. z o\.o\./)
 assert.doesNotMatch(briefText,/Stronoskop|Nagłówki HTTP|Lista narzędzi|Pozostałe obserwacje/)
 const cvePage=pages.find(page=>page.includes('Co sprawdzić w pierwszej kolejności'))
 assert.ok(cvePage)
 assert.match(cvePage,/CVE-2025-4242/)
 const contactPage=pages.at(-1)
 const requiredScope='Raport przygotowała firma Codefellow Sp. z o.o. przy użyciu narzędzia Codefellow Scout. Dokument przedstawia wybrane, najważniejsze obserwacje z pasywnej analizy publicznie dostępnej strony. Ma charakter informacyjny i nie stanowi pełnego audytu bezpieczeństwa. Wskazane dopasowania CVE wymagają weryfikacji przez administratora serwisu. W razie pytań dotyczących przedstawionych ustaleń prosimy o kontakt.'
 assert.ok(contactPage.replace(/\s+/gu,' ').includes(requiredScope))
 assert.match(contactPage,/Zakres i kontakt/)
 assert.match(contactPage,/kontakt@codefellow\.pl/)
 assert.match(contactPage,/\+48 795 309 804/)
 assert.doesNotMatch(pages.slice(0,-1).join(' '),/kontakt@codefellow\.pl|\+48 795 309 804/)
 assert.equal(briefDocumentDefinition(model).info.author,'Codefellow Sp. z o.o.')
 assert.equal(documentDefinition(model).info.author,'Stronoskop')
 const longDomain='www.powiat-starachowice-with-a-long-subdomain.example.gov.pl'
 const longUrl=`https://${longDomain}/`
 const longScan={...scan,url:longUrl,final_url:longUrl,findings:scan.findings.map(item=>({...item,url:longUrl}))}
 const longModel=await prepareBriefModel(longScan)
 const longText=await pdfText(await renderBriefPrepared(longModel,true))
 const longPages=longText.split('\f').filter(page=>page.trim())
 assert.ok(longPages.length>=3&&longPages.length<=4)
 assert.ok(longPages.every(page=>page.trim().length>100))
 assert.ok(longText.includes(longDomain))
 const longRecommendation=model.brief_cves.items[0].recommendation.replace(/\s+/gu,' ')
 assert.ok(longText.replace(/\s+/gu,' ').includes(longRecommendation))
 assert.match(longPages.at(-1),/Zakres i kontakt/)
 const fullText=await pdfText(await renderPrepared(await prepareModel(scan)))
 assert.match(fullText,/Stronoskop/)
 assert.doesNotMatch(fullText,/Codefellow Scout/)
})

test('Brief selection yields no CVEs when there is no reliable match',async()=>{
 const model=await prepareBriefModel({...base,cves:[]})
 assert.equal(model.brief_cves.items.length,0)
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

test('CLI preserves full output and brief skips scans without selected CVEs',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'report-cli-'));try{
  const input=join(dir,'input'),output=join(dir,'output');await (await import('node:fs/promises')).mkdir(input)
  await writeFile(join(input,'a.json'),JSON.stringify(base))
  await writeFile(join(input,'b.json'),JSON.stringify({...base,scan_id:'fixture-2',findings:[finding]}))
  await exec(process.execPath,['generate.mjs','--input',input,'--output',output,'--version','full'],{cwd:root})
  assert.equal((await readdir(output)).filter(f=>f.endsWith('.pdf')).length,2)
  await exec(process.execPath,['generate.mjs','--input',input,'--output',output],{cwd:root})
  assert.equal((await readdir(output)).filter(f=>f.endsWith('.pdf')).length,2)

  const briefInput=join(dir,'brief-input'),briefOutput=join(dir,'brief-output')
  await (await import('node:fs/promises')).mkdir(briefInput)
  const cve={cve_id:'CVE-2025-4242',product:'PHP',technology_name:'PHP',detected_version:'8.2.4',
   match_status:'potentially_affected',confidence:'medium',backport_status:'unknown',sources:['NVD'],
   affected_range:'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*',description:'The parse_str function can overwrite arbitrary variables.',
   vendor_advisories:['https://bugs.php.net/bug.php?id=68665'],cvss_score:7.5}
  const technology={name:'PHP',version:'8.2.4',version_status:'declared',sources:['http_headers'],
   version_conflict:false,cpe:'cpe:2.3:a:php:php:8.2.4:*:*:*:*:*:*:*'}
  const csp={pluginId:'10038',alertRef:'10038-1',name:'Content Security Policy (CSP) Header Not Set',
   risk:'Medium',confidence:'Low',url:'https://no-cve.example.org/',evidence:''}
  const noCve={...base,scan_id:'no-cve',url:'https://no-cve.example.org/',final_url:'https://no-cve.example.org/',
   raw_zap:{alerts:[csp]}}
  const rejected={...base,scan_id:'rejected',url:'https://rejected.example.org/',final_url:'https://rejected.example.org/',
   technologies:[technology],cves:[{...cve,match_status:'not_affected'}],raw_zap:{alerts:[csp]}}
  const qualified={...base,scan_id:'qualified',url:'https://qualified.example.org/',final_url:'https://qualified.example.org/',
   technologies:[technology],cves:[cve],raw_zap:{alerts:[{...csp,url:'https://qualified.example.org/'}]}}
  await writeFile(join(briefInput,'a-no-cve.json'),JSON.stringify(noCve))
  await writeFile(join(briefInput,'b-rejected.json'),JSON.stringify(rejected))
  await writeFile(join(briefInput,'c-qualified.json'),JSON.stringify(qualified))
  const {stdout}=await exec(process.execPath,['generate.mjs','--input',briefInput,'--output',briefOutput,'--brief'],{cwd:root})
  assert.match(stdout,/no-cve\.example\.org — pominięto: brak kwalifikujących się CVE/)
  assert.match(stdout,/rejected\.example\.org — pominięto: brak kwalifikujących się CVE/)
  assert.match(stdout,/Zapisane raporty: 1\. Pominięte: 2\. Błędy: 0\./)
  const files=(await readdir(briefOutput)).filter(f=>f.endsWith('.pdf'))
  assert.equal(files.length,1)
  assert.match(files[0],/--brief\.pdf$/)
  assert.ok(files.every(file=>file.endsWith('--brief.pdf')))
  const text=await pdfText(await readFile(join(briefOutput,files[0])))
  const pages=text.split('\f').filter(page=>page.trim())
  assert.equal(pages.length,3)
  assert.match(pages[1],/Polityka bezpieczeństwa treści \(CSP\)/)
  assert.match(pages.at(-1),/Zakres i kontakt/)
  assert.match(pages.at(-1),/kontakt@codefellow\.pl/)
  assert.match(pages.at(-1),/\+48 795 309 804/)
  const {stdout:whiteStdout}=await exec(process.execPath,['generate.mjs','--input',briefInput,'--output',briefOutput,'--brief-white'],{cwd:root})
  assert.match(whiteStdout,/Zapisane raporty: 1\. Pominięte: 2\. Błędy: 0\./)
  const darkAndWhite=(await readdir(briefOutput)).filter(f=>f.endsWith('.pdf'))
  assert.equal(darkAndWhite.length,2)
  assert.ok(darkAndWhite.some(file=>file.endsWith('--brief.pdf')))
  assert.ok(darkAndWhite.some(file=>file.endsWith('--brief-white.pdf')))
  const whiteName=darkAndWhite.find(file=>file.endsWith('--brief-white.pdf'))
  const whiteText=await pdfText(await readFile(join(briefOutput,whiteName)))
 assert.match(whiteText,/DO SPRAWDZENIA/)
  const whitePages=whiteText.split('\f').filter(page=>page.trim())
  assert.equal(whitePages.length,3)
  const sharedModel=await prepareBriefModel(qualified)
  for(const id of ['CVE-2025-4242']) {
   assert.match(text,new RegExp(id))
   assert.match(whiteText,new RegExp(id))
  }
 const sharedRecommendation=sharedModel.brief_cves.items[0].recommendation.replace(/\s+/gu,' ')
 assert.ok(text.replace(/\s+/gu,' ').includes(sharedRecommendation))
 assert.ok(whiteText.replace(/\s+/gu,' ').includes(sharedRecommendation))

  const singleInput=join(dir,'single-input')
  await (await import('node:fs/promises')).mkdir(singleInput)
  await writeFile(join(singleInput,'qualified.json'),JSON.stringify(qualified))
  await exec(process.execPath,['generate.mjs','--input',singleInput,'--output',briefOutput],{cwd:root})
  const allVariants=(await readdir(briefOutput)).filter(file=>file.endsWith('.pdf'))
  assert.equal(allVariants.length,3)
  assert.ok(allVariants.some(file=>file.endsWith('--analiza.pdf')))
  assert.ok(allVariants.some(file=>file.endsWith('--brief.pdf')))
  assert.ok(allVariants.some(file=>file.endsWith('--brief-white.pdf')))

  const skipInput=join(dir,'white-skip-input'),skipOutput=join(dir,'white-skip-output')
  await (await import('node:fs/promises')).mkdir(skipInput)
  await writeFile(join(skipInput,'no-cve.json'),JSON.stringify(noCve))
  await writeFile(join(skipInput,'rejected.json'),JSON.stringify(rejected))
  const {stdout:skipStdout}=await exec(process.execPath,['generate.mjs','--input',skipInput,'--output',skipOutput,'--brief-white'],{cwd:root})
  assert.match(skipStdout,/no-cve\.example\.org — pominięto: brak kwalifikujących się CVE/)
  assert.match(skipStdout,/rejected\.example\.org — pominięto: brak kwalifikujących się CVE/)
  assert.match(skipStdout,/Zapisane raporty: 0\. Pominięte: 2\. Błędy: 0\./)
  assert.equal((await readdir(skipOutput)).length,0)
 }finally{await rm(dir,{recursive:true,force:true})}
})
