import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';

function setup(existing){
 const listeners=new Map(),sent=[],announcements=[],timers=new Set();
 const page={ethereum:existing,addEventListener(n,f){if(!listeners.has(n))listeners.set(n,[]);listeners.get(n).push(f)},dispatchEvent(e){for(const f of listeners.get(e.type)||[])f(e);return true},postMessage(m,origin){sent.push({m,origin})}};
 page.addEventListener('eip6963:announceProvider',e=>announcements.push(e.detail));
 const context=vm.createContext({window:page,location:{origin:'https://fixture.example'},crypto:webcrypto,TextEncoder,Event:class{constructor(type){this.type=type}},CustomEvent:class{constructor(type,options){this.type=type;this.detail=options.detail}},setTimeout(fn,ms){const id=setTimeout(fn,ms);id.unref();timers.add(id);return id},clearTimeout(id){clearTimeout(id);timers.delete(id)}});
 vm.runInContext(readFileSync('extension/dist/provider.js','utf8'),context);
 const receive=(data,origin='https://fixture.example',source=page)=>page.dispatchEvent({type:'message',data:{target:'grexie-vault:page',version:1,...data},origin,source});
 return {page,p:page.grexieVault,sent,announcements,receive,clean(){for(const id of timers)clearTimeout(id)}};
}
const plain=x=>JSON.parse(JSON.stringify(x));
test('EIP-6963 stable identity, legacy coexistence and rediscovery',()=>{
 const other={other:true},s=setup(other);try{assert.equal(s.page.ethereum,other);assert.equal(s.announcements[0].provider,s.p);assert.equal(s.announcements[0].info.rdns,'com.grexie.vault');assert.equal(s.announcements[0].info.name,'Grexie Vault');s.page.dispatchEvent({type:'eip6963:requestProvider'});assert.equal(s.announcements.length,2);assert.equal(s.announcements[0].info.uuid,s.announcements[1].info.uuid);assert(Object.isFrozen(s.announcements[0].info));}finally{s.clean()}
 const alone=setup();assert.equal(alone.page.ethereum,alone.p);alone.clean();
});
test('required methods preserve exact params, results and provider errors',async()=>{
 const s=setup();try{for(const method of ['eth_accounts','eth_requestAccounts','eth_chainId','net_version','eth_sendTransaction','eth_signTransaction','personal_sign','eth_sign','eth_signTypedData','eth_signTypedData_v1','eth_signTypedData_v3','eth_signTypedData_v4','wallet_switchEthereumChain','wallet_addEthereumChain','wallet_getPermissions','wallet_requestPermissions','wallet_revokePermissions','eth_getBalance','eth_call','eth_estimateGas','eth_getCode','eth_getLogs','eth_getTransactionByHash','eth_getTransactionReceipt','eth_blockNumber','eth_feeHistory','eth_gasPrice']){
  const params=['exact',{'value':'9007199254740993'}],pending=s.p.request({method,params});const {m,origin}=s.sent.at(-1);assert.equal(origin,'https://fixture.example');assert.equal(m.method,method);assert.deepEqual(plain(m.params),params);s.receive({id:m.id,result:'exact-result'});assert.equal(await pending,'exact-result');
 }
 const pending=s.p.request({method:'eth_requestAccounts'}),id=s.sent.at(-1).m.id;s.receive({id,error:{code:4001,message:'User rejected'}});await assert.rejects(pending,e=>e.code===4001&&e.message==='User rejected');
 for(const method of ['personal_ѕign','eth_🚀','_changeIdentity','x'.repeat(81)])await assert.rejects(s.p.request({method}),e=>[-32602,4200].includes(e.code));
 await assert.rejects(s.p.request({method:'eth_call',params:{}}),e=>e.code===-32602);
 }finally{s.clean()}
});
test('origin isolation, account/chain lifecycle, listener removal and navigation cancellation',async()=>{
 const s=setup(),events=[];try{for(const name of ['connect','disconnect','accountsChanged','chainChanged'])s.p.on(name,value=>events.push({name,value}));const address='0x'+'a'.repeat(40);s.receive({event:'state',state:{available:true,accounts:[address],chainId:'0x2105'}},'https://attacker.example');assert.equal(s.p.isConnected(),false);
 s.receive({event:'state',state:{available:true,accounts:[address],chainId:'0x2105'}});assert(s.p.isConnected());assert.equal(s.p.selectedAddress,address);assert.equal(s.p.chainId,'0x2105');assert.equal(s.p.networkVersion,'8453');assert.deepEqual(events.map(e=>e.name),['connect','accountsChanged','chainChanged']);
 const removed=()=>assert.fail('removed listener ran');s.p.on('accountsChanged',removed).removeListener('accountsChanged',removed);s.receive({event:'state',state:{available:true,accounts:[],chainId:'0x2105'}});assert.equal(s.p.selectedAddress,null);assert.deepEqual(plain(events.at(-1).value),[]);
 const pending=s.p.request({method:'personal_sign',params:['0x00',address]}),id=s.sent.at(-1).m.id;s.page.dispatchEvent({type:'pagehide'});await assert.rejects(pending,e=>e.code===4900);assert.equal(s.sent.at(-1).m.cancel,id);s.receive({event:'state',state:{available:false,accounts:[],chainId:'0x2105'}});assert.equal(events.at(-1).name,'disconnect');assert.equal(events.at(-1).value.code,4900);
 }finally{s.clean()}
});
