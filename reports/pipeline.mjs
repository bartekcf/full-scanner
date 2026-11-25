import {spawn} from 'node:child_process'
import {fileURLToPath} from 'node:url'
const root=fileURLToPath(new URL('.',import.meta.url))
export function child(command,args,input,maxOutput=24*1024*1024,cwd=root){
 return new Promise((resolve,reject)=>{
  const p=spawn(command,args,{cwd,stdio:['pipe','pipe','pipe'],windowsHide:true})
  const chunks=[];let size=0,err='',settled=false
  const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);error?reject(error):resolve(value)}
  const timer=setTimeout(()=>{p.kill('SIGKILL');finish(new Error('Przekroczono limit czasu przetwarzania (90 s).'))},90000)
  p.on('error',()=>finish(new Error('Nie można uruchomić procesu. Sprawdź Python 3 i zależności raportowania.')))
  p.stdout.on('data',c=>{size+=c.length;if(size>maxOutput){p.kill('SIGKILL');finish(new Error('Przekroczono limit rozmiaru wyniku.'))}else chunks.push(c)})
  p.stderr.on('data',c=>{if(err.length<2000)err+=c.toString()})
  p.stdin.on('error',()=>{})
  p.on('close',code=>finish(code===0?null:new Error('Proces raportowania zakończył się błędem. '+err.replace(/[^\p{L}\p{N}\s:().-]/gu,'').slice(0,250)),Buffer.concat(chunks)))
  p.stdin.end(input)
 })
}
export async function validateCatalog(){return JSON.parse((await child(process.env.REPORT_PYTHON||'python3',['prepare.py','--validate'],'')).toString())}

async function prepare(scan, args) {
 return JSON.parse((await child(process.env.REPORT_PYTHON||'python3',['prepare.py',...args],JSON.stringify(scan))).toString())
}
export async function prepareModel(scan){return prepare(scan,[])}
export async function prepareBriefModel(scan){return prepare(scan,['--brief'])}
export async function renderPrepared(model){return child(process.execPath,['--max-old-space-size=384','render-worker.mjs'],JSON.stringify(model),32*1024*1024)}
export async function renderBriefPrepared(model, white=false){
 return child(process.execPath,['--max-old-space-size=384','render-worker.mjs',white?'--brief-white':'--brief'],JSON.stringify(model),32*1024*1024)
}

export async function registerReport(output, scanId, pdf) {
 const project = fileURLToPath(new URL('..', import.meta.url))
 await child(process.env.REPORT_PYTHON || 'python3',
   ['-m', 'app.results', '--output', output, '--register-report', scanId, pdf], '', undefined, project)
}
