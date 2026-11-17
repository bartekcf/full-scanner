import {renderModel} from './render-model.mjs'
import {restrictRendererIO} from './renderer-sandbox.mjs'
restrictRendererIO()
try{
 const chunks=[];let size=0
 for await(const chunk of process.stdin){size+=chunk.length;if(size>20*1024*1024)throw new Error('Model too large');chunks.push(chunk)}
 const model=JSON.parse(Buffer.concat(chunks).toString('utf8'))
 const pdf=await renderModel(model)
 process.stdout.write(pdf)
}catch(error){process.stderr.write('PDF rendering failed: '+error.constructor.name+'\n');process.exitCode=1}
