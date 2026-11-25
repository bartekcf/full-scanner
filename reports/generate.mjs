import {createHash} from 'node:crypto'
import {mkdir,readdir,readFile,stat,writeFile,rename,rm} from 'node:fs/promises'
import {basename,dirname,join,resolve} from 'node:path'
import {parseArgs} from 'node:util'
import {validateCatalog,prepareModel,prepareBriefModel,registerReport,renderPrepared,renderBriefPrepared} from './pipeline.mjs'

async function* jsonFiles(dir,output,depth=0){
 if(depth>20)throw new Error('Przekroczono głębokość katalogów.')
 for(const entry of (await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))){
  const path=join(dir,entry.name)
  if(resolve(path)===output)continue
  if(entry.isDirectory())yield* jsonFiles(path,output,depth+1)
  else if(entry.isFile()&&entry.name.endsWith('.json')&&entry.name!=='manifest.json')yield path
 }
}
const slug=value=>value.toLowerCase().normalize('NFKD').replace(/\p{Mark}/gu,'').replace(/[^a-z0-9.-]+/g,'-').replace(/^[.-]+|[.-]+$/g,'').slice(0,150)||'strona'
async function atomic(path,data){const tmp=path+'.'+process.pid+'.tmp';try{await writeFile(tmp,data,{mode:0o600});await rename(tmp,path)}finally{await rm(tmp,{force:true})}}
async function main(){
 const {values}=parseArgs({options:{input:{type:'string'},output:{type:'string'},version:{type:'string'},'database-dir':{type:'string'},brief:{type:'boolean'},'brief-white':{type:'boolean'},help:{type:'boolean'}}})
 if(values.help){console.log('node reports/generate.mjs --input KATALOG_JSON --output KATALOG_PDF [--database-dir KATALOG_SKANOW] [--brief | --brief-white]');return}
 if(!values.input||!values.output)throw new Error('Podaj --input oraz --output.')
 if(values.version&&!['summary','full'].includes(values.version))throw new Error('Nieznany dawny wariant raportu.')
 if(values.brief&&values['brief-white'])throw new Error('Wybierz jeden wariant skrócony: --brief albo --brief-white.')
 if(values.version)console.error('Opcja --version jest zgodna wstecznie; powstaje jeden kompletny raport.')
 await validateCatalog()
 const output=resolve(values.output)
 if(output===resolve(values.input))throw new Error('Katalog wynikowy musi różnić się od wejściowego.')
 await mkdir(output,{recursive:true})
 const isBrief=Boolean(values.brief||values['brief-white'])
 let generated=0,failed=0,visited=0,skipped=0;const seen=new Set()
 for await(const path of jsonFiles(values.input,output)){
  if(++visited>10000)throw new Error('Przekroczono limit 10000 plików.')
  let sourceId=createHash('sha256').update(path).digest('hex').slice(0,16)
  try{
   if((await stat(path)).size>64*1024*1024)throw new Error('Plik przekracza 64 MiB.')
   const scan=JSON.parse(await readFile(path,'utf8'))
   if(!scan||!['completed','failed'].includes(scan.status)||!scan.scan_id)continue
   if(seen.has(scan.scan_id))continue
   const model=isBrief?await prepareBriefModel(scan):await prepareModel(scan);sourceId=model.metadata.report_id
   const cveCount=Array.isArray(model.brief_cves?.items)?model.brief_cves.items.length:0
   if(isBrief&&!cveCount){
    console.log(`${model.metadata.domain} — pominięto: brak kwalifikujących się CVE`)
    skipped++;seen.add(scan.scan_id)
    continue
   }
   const date=model.metadata.scanned_at?.slice(0,10)||'brak-daty'
   const stem=slug(model.metadata.domain)+'--'+date
   const contentId=model.diagnostics.source_digest.slice(0,12)
   const name=stem+'--'+contentId+'--analiza.pdf'
   const outputName=values['brief-white']?name.slice(0,-4)+'--brief-white.pdf':values.brief?name.slice(0,-4)+'--brief.pdf':name
   const destination=join(output,outputName)
   const pdf=isBrief?await renderBriefPrepared(model,Boolean(values['brief-white'])):await renderPrepared(model)
   await atomic(destination,pdf)
   const batch = dirname(resolve(path))
   const resultsDir = dirname(batch)
   let databaseDir = values['database-dir'] && resolve(values['database-dir'])
   if (!databaseDir && basename(batch).startsWith('batch-') && resultsDir === dirname(output)) {
    const database = await stat(join(resultsDir, 'scans.sqlite3')).catch(error => {
     if (error.code !== 'ENOENT') throw error
    })
    if (database?.isFile()) databaseDir = resultsDir
   }
   if (databaseDir) await registerReport(databaseDir, scan.scan_id, destination)
   for(const warning of model.diagnostics.warnings)console.error(sourceId+': '+warning)
   const cveStatus=isBrief?`; CVE: ${cveCount} wybranych`:''
   console.log(`[${++generated}] ${outputName}${cveStatus}`);seen.add(scan.scan_id)
  }catch(error){failed++;console.error(sourceId+': '+(error instanceof SyntaxError?'Nieprawidłowy JSON.':error.message))}
 }
 if(isBrief)console.log(`Zapisane raporty: ${generated}. Pominięte: ${skipped}. Błędy: ${failed}.`)
 else console.log(`Zapisane raporty: ${generated}. Błędy: ${failed}.`)
 if(failed||(!generated&&!skipped))process.exitCode=1
}
main().catch(error=>{console.error(error.message);process.exitCode=1})
