declare const VAULT_ICON: string;
type Listener=(value:unknown)=>void;
type ProviderError=Error&{code:number;data?:unknown};
const error=(code:number,message:string):ProviderError=>Object.assign(new Error(message),{code});
const utf8=new TextEncoder();
const publicMethod=/^(?:(?:eth_|net_|web3_|wallet_)[A-Za-z0-9_]+|personal_sign)$/;
class VaultProvider {
 readonly isGrexieVault=true;
 #listeners=new Map<string,Set<Listener>>();
 #requests=new Map<string,{resolve:(v:unknown)=>void;reject:(e:ProviderError)=>void;timer:ReturnType<typeof setTimeout>}>();
 #available=false;
 #accounts:string[]=[];
 #chainId="0x1";
 constructor(){
  window.addEventListener("message",event=>{
   if(event.source!==window||event.origin!==location.origin||!event.data||event.data.target!=="grexie-vault:page"||event.data.version!==1)return;
   const message=event.data;
   if(message.event==="state"){
    const state=message.state;if(!state||typeof state.available!=="boolean")return;
    if(state.available&&!this.#available)this.#emit("connect",{chainId:state.chainId||this.#chainId});
    if(!state.available&&this.#available)this.#emit("disconnect",error(4900,"Vault unavailable"));this.#available=state.available;
    const accounts=state.available&&Array.isArray(state.accounts)?state.accounts:[];
    if(accounts.every((a:unknown)=>typeof a==="string"&&/^0x[0-9a-fA-F]{40}$/.test(a as string))&&JSON.stringify(accounts)!==JSON.stringify(this.#accounts)){this.#accounts=accounts;this.#emit("accountsChanged",[...accounts]);}
    if(typeof state.chainId==="string"&&/^0x[0-9a-f]+$/.test(state.chainId)&&state.chainId!==this.#chainId){this.#chainId=state.chainId;this.#emit("chainChanged",this.#chainId);}return;
   }
   if(typeof message.id!=="string")return;const request=this.#requests.get(message.id);if(!request)return;clearTimeout(request.timer);this.#requests.delete(message.id);
   if(message.error&&Number.isInteger(message.error.code)&&typeof message.error.message==="string")request.reject(error(message.error.code,message.error.message));else request.resolve(message.result??null);
  });
  window.addEventListener("pagehide",()=>{for(const [id,p]of this.#requests){clearTimeout(p.timer);p.reject(error(4900,"Page disconnected"));window.postMessage({target:"grexie-vault:content",version:1,cancel:id},location.origin)}this.#requests.clear()});
 }
 request(args:{method:string;params?:readonly unknown[]|object}):Promise<unknown>{
  if(!args||typeof args.method!=="string"||args.params!==undefined&&!Array.isArray(args.params))return Promise.reject(error(-32602,"Invalid wallet request"));
  if(args.method.length>80||!publicMethod.test(args.method))return Promise.reject(error(4200,"Unsupported wallet method"));
  try{if(utf8.encode(JSON.stringify(args.params||[])).byteLength>180*1024)return Promise.reject(error(-32602,"Wallet request exceeds size limit"))}catch{return Promise.reject(error(-32602,"Invalid wallet parameters"))}
  if(this.#requests.size>=32)return Promise.reject(error(-32002,"Too many pending requests"));
  const id=crypto.randomUUID();return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.#requests.delete(id);window.postMessage({target:"grexie-vault:content",version:1,cancel:id},location.origin);reject(error(4001,"Vault request expired"))},11*60*1000);this.#requests.set(id,{resolve,reject,timer});try{window.postMessage({target:"grexie-vault:content",version:1,id,method:args.method,params:args.params||[]},location.origin)}catch{clearTimeout(timer);this.#requests.delete(id);reject(error(-32602,"Invalid wallet parameters"))}});
 }
 on(event:string,listener:Listener){if(typeof listener!=="function")throw error(-32602,"Listener must be a function");let set=this.#listeners.get(event);if(!set){set=new Set();this.#listeners.set(event,set)}set.add(listener);return this}
 removeListener(event:string,listener:Listener){this.#listeners.get(event)?.delete(listener);return this}
 removeAllListeners(event?:string){if(event)this.#listeners.delete(event);else this.#listeners.clear();return this}
 isConnected(){return this.#available}
 get selectedAddress(){return this.#accounts[0]||null}
 get chainId(){return this.#chainId}
 get networkVersion(){return BigInt(this.#chainId).toString()}
 enable(){return this.request({method:"eth_requestAccounts"})}
 // Compatibility for older web3.js clients; all paths share request validation.
 sendAsync(payload:{id:unknown;method:string;params?:unknown[]},callback:(e:ProviderError|null,r?:unknown)=>void){this.request(payload).then(result=>callback(null,{jsonrpc:"2.0",id:payload.id,result}),e=>callback(e))}
 send(method:string|{id:unknown;method:string;params?:unknown[]},params?:unknown[]|((e:ProviderError|null,r?:unknown)=>void)):unknown{if(typeof method==="string")return this.request({method,params:Array.isArray(params)?params:[]});if(typeof params==="function")return this.sendAsync(method,params);return this.request(method)}
 #emit(event:string,value:unknown){for(const listener of this.#listeners.get(event)||[]){try{listener(value)}catch{ /* a dApp listener cannot break the provider */ }}}
}
const provider=new VaultProvider();
const detail=Object.freeze({info:Object.freeze({uuid:crypto.randomUUID(),name:"Grexie Vault",icon:VAULT_ICON,rdns:"com.grexie.vault"}),provider});
const announce=()=>window.dispatchEvent(new CustomEvent("eip6963:announceProvider",{detail}));
window.addEventListener("eip6963:requestProvider",announce);announce();
const page=window as Window&{ethereum?:unknown;grexieVault?:unknown};
if(!page.ethereum){try{Object.defineProperty(page,"ethereum",{value:provider,writable:false,configurable:true});window.dispatchEvent(new Event("ethereum#initialized"))}catch{}}
Object.defineProperty(page,"grexieVault",{value:provider,writable:false,configurable:false});
