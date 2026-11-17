import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp,writeFile,rm,readdir} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {execFile} from 'node:child_process'
import {promisify} from 'node:util'
import {fileURLToPath} from 'node:url'
import {prepareModel,renderPrepared,child} from '../pipeline.mjs'
import {documentDefinition} from '../render-model.mjs'
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
 assert.match(pages[0],/Zakres analizy jest niepełny/);assert.match(pages[0],/Zalecamy/)
 assert.ok(pages.every(t=>t.replace(/AudytorAI.*|Strona \d+ \/ \d+/g,'').trim().length>100))
 assert.doesNotMatch(txt,/\{target\}|\{date\}|undefined|\bNone\b|JSON|potwierdzona luka/)
 assert.match(txt,/U-01/)
})

test('Sandbox rejects network and arbitrary filesystem reads',async()=>{
 const script=`import {restrictRendererIO} from './renderer-sandbox.mjs'; import fs from 'node:fs'; import http from 'node:http'; import net from 'node:net'; import dns from 'node:dns'; restrictRendererIO(); let blocked=0; for (const f of [()=>http.get('http://127.0.0.1/'),()=>net.connect(80,'127.0.0.1'),()=>dns.lookup('example.org'),()=>fetch('https://example.org'),()=>fs.readFileSync('/etc/passwd')]){try{f()}catch{blocked++}}; console.log(blocked)`
 const result=await child(process.execPath,['--input-type=module','-e',script],'')
 assert.equal(result.toString().trim(),'5')
})

test('Untrusted evidence never becomes markup, images, links or secrets',async()=>{
 const scan={...base,findings:[{...finding,id:'9999',title:'Unknown rule',evidence:'<img src="http://127.0.0.1/private"><script>SECRET</script> Authorization: Bearer SECRET'}]}
 const model=await prepareModel(scan)
 const definition=documentDefinition(model)
 assert.doesNotMatch(JSON.stringify(definition),/SECRET|127\.0\.0\.1|"image":|"svg":|"link":/)
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
 }finally{await rm(dir,{recursive:true,force:true})}
})
