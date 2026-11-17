import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import tls from 'node:tls'
import dns from 'node:dns'
import fs from 'node:fs'
import {syncBuiltinESMExports} from 'node:module'
export function restrictRendererIO(){
const denied=()=>{throw new Error('Renderer I/O is disabled')}
for(const mod of [http,https]){mod.request=denied;mod.get=denied}
net.connect=denied;net.createConnection=denied;net.Socket.prototype.connect=denied;tls.connect=denied
for(const key of ['lookup','resolve','resolve4','resolve6','reverse']){dns[key]=denied;if(dns.promises[key])dns.promises[key]=denied}
globalThis.fetch=denied
for(const key of ['readFile','readFileSync','open','openSync','createReadStream','readdir','readdirSync','opendir','opendirSync'])fs[key]=denied
for(const key of ['readFile','open','readdir','opendir'])fs.promises[key]=denied
syncBuiltinESMExports()
}
