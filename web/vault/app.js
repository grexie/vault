import {optionsFromJSON, publicCredential} from "/passkey.js";
import {b64, unb64, b64url, bytes, seal, open, prfKey, newRoot, sign, envelope, verify, digest, openEnvelope} from "/crypto.js";
import {verifiedABIs, downloadABI} from "/sourcify.js";
const $ = (id) => document.getElementById(id);
let session, root, vault, wrappedKey, credentialID, version = 0, mode = "generate", restoring = false, backupFile, restorePreview;
let epoch=0;
let worker, nextID=0;const pending=new Map();
let toastTimer;
function toast(message,error=false){$("toast").textContent=message;$("toast").classList.toggle("error",error);$("toast").hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$("toast").hidden=true,error?12000:5000);}
async function action(button,fn){if(button?.disabled)return; if(button)button.disabled=true;try{return await fn();}catch(e){toast(e.message||"Something went wrong. Please try again.",true);}finally{if(button)button.disabled=false;}}
async function api(path,body,method=body===undefined?"GET":"POST"){
 const generation=epoch;
 const r=await fetch("/api/v1"+path,{method,headers:{"Content-Type":"application/json"},credentials:"same-origin",cache:"no-store",body:body===undefined?undefined:JSON.stringify(body)});
 const data=await r.json();if(generation!==epoch)throw new Error("Session changed; operation cancelled");if(!r.ok){if(r.status===401){lock();}throw new Error(data.error||"Request failed");}return data;
}
function work(input){
 if(!root||!session)return Promise.reject(new Error("Vault is locked"));
 if(!worker){worker=new Worker("/worker.js");worker.onmessage=({data})=>{if(data.ready)return;const waiter=pending.get(data.id);if(!waiter)return;pending.delete(data.id);data.error?waiter.reject(new Error(data.error)):waiter.resolve(data.result);};worker.onerror=()=>{for(const p of pending.values())p.reject(new Error("Browser worker failed. Reload before trying again."));pending.clear();worker.terminate();worker=null;};}
 const id=++nextID;return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});worker.postMessage({id,input});});
}
function show(view){for(const id of ["auth-view","unlock-view","vault-view"])$(id).hidden=id!==view;$("signout").hidden=view==="auth-view";}
function lock(){
 epoch++;
 if(session)localStorage.removeItem(cacheName());
 if(worker){worker.terminate();worker=null;}
 for(const waiter of pending.values())waiter.reject(new Error("Vault locked; operation cancelled"));pending.clear();
 root=null;vault=null;session=null;wrappedKey=null;credentialID=null;version=0;
 backupFile=null;restorePreview=null;selectedRequest=null;providers=null;
 for(const form of document.querySelectorAll("form"))form.reset();
 for(const input of document.querySelectorAll("input,textarea"))if(input.type!=="button"&&input.type!=="submit")input.value="";
 for(const dialog of document.querySelectorAll("dialog[open]"))dialog.close();
 for(const id of ["identity-list","device-list","owner-list","request-list","review-content","restore-preview","credential-fields"])$(id)?.replaceChildren();
 show("auth-view");
}
function node(tag,text,className){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(className)e.className=className;return e;}
function cacheName(){return "grexie-vault/unlock/v1/"+session.userId;}
async function remember(){
 const wrapping=await api("/session/wrapping-key",{});const key=unb64(wrapping.key);
 try{const generation=epoch;const box=await seal(key,wrapping.context,root);if(generation!==epoch||!session)throw new Error("Vault locked");localStorage.setItem(cacheName(),JSON.stringify({context:wrapping.context,box,expiresAt:wrapping.expiresAt}));}finally{key.fill(0);}
}
async function rehydrate(){
 const cache=cacheName(),generation=epoch;const text=localStorage.getItem(cache);if(!text)return false;
 try{const saved=JSON.parse(text);if(Date.parse(saved.expiresAt)<=Date.now())throw new Error("expired");const wrapping=await api("/session/wrapping-key",{});if(wrapping.context!==saved.context)throw new Error("session changed");const key=unb64(wrapping.key);try{const opened=await open(key,saved.context,saved.box);if(generation!==epoch)throw new Error("Vault locked");root=opened;}finally{key.fill(0);}await loadData();return true;
 }catch{root=null;localStorage.removeItem(cache);return false;}
}
async function loadData(){
 const generation=epoch;
 const record=await api("/vault");version=record.version;
 if(!record.vault){vault={version:1,identities:[],devices:[],delegates:[]};return;}
 wrappedKey=record.vault.wrappedKey;credentialID=record.vault.credential;
 const key=unb64(root.key);try{const opened=await open(key,`grexie-vault/data/v1:${session.userId}:${version}`,record.vault.data);if(generation!==epoch)throw new Error("Vault locked");vault=opened;}finally{key.fill(0);}
 if(vault.version!==1 || !Array.isArray(vault.identities))throw new Error("Unsupported vault data");
 vault.devices??=[];vault.delegates??=[];
 show("vault-view");render();
}
async function publishCatalog(){
 const identities=vault.identities.map(({secret,...publicIdentity})=>publicIdentity);
 const signed=await sign(root,"catalog",{ownerId:session.userId,identities,updatedAt:new Date().toISOString()});
 for(const device of vault.devices){const box=await envelope(device.boxPublic,`catalog:${device.id}`,signed);try{await api("/catalog",{deviceId:device.id,box});}catch(e){toast("Saved. Public identity sync needs another try.",true);}}
}
async function save(next){
 const generation=epoch;
 if(!root||!session)throw new Error("Vault is locked");
 const key=unb64(root.key);let data;try{data=await seal(key,`grexie-vault/data/v1:${session.userId}:${version+1}`,next);}finally{key.fill(0);}
 if(generation!==epoch)throw new Error("Vault locked; save cancelled");
 const result=await api("/vault",{version,vault:{wrappedKey,data,credential:credentialID}},"PUT");
 if(generation!==epoch)throw new Error("Vault locked; save cancelled");version=result.version;vault=next;show("vault-view");render();await publishCatalog();
}
async function unlockWith(credential){
 const generation=epoch;
 const prf=credential.getClientExtensionResults().prf?.results?.first;
 const key=await prfKey(prf,session.userId,credential.id);
 const record=await api("/vault");version=record.version;credentialID=credential.id;
 try{
  if(record.vault){if(record.vault.credential!==credential.id)throw new Error("This vault is encrypted for a different passkey");wrappedKey=record.vault.wrappedKey;const opened=await open(key,`grexie-vault/root/v1:${session.userId}:${credential.id}`,wrappedKey);if(generation!==epoch)throw new Error("Vault locked");root=opened;await loadData();}
  else{const created=await newRoot();if(generation!==epoch)throw new Error("Vault locked");root=created;wrappedKey=await seal(key,`grexie-vault/root/v1:${session.userId}:${credential.id}`,root);vault={version:1,identities:[],devices:[],delegates:[]};await save(vault);}
 }finally{key.fill(0);if(prf)new Uint8Array(prf).fill(0);}
 await remember();
}
async function freshPasskey(purpose=""){
 const start=await api("/auth/unlock/begin",{purpose});const credential=await navigator.credentials.get({publicKey:optionsFromJSON(start.options)});
 const result=await api("/auth/unlock/finish",{ceremony:start.ceremony,credential:publicCredential(credential,start.options)});return {credential,verification:result.verification};
}
$("login").onclick=()=>action($("login"),async()=>{
 const start=await api("/auth/login/begin",{});const credential=await navigator.credentials.get({publicKey:optionsFromJSON(start.options)});
 await api("/auth/login/finish",{ceremony:start.ceremony,credential:publicCredential(credential,start.options)});session=await api("/session");show("unlock-view");await unlockWith(credential);
});
$("register-form").onsubmit=(event)=>{event.preventDefault();action(event.submitter,async()=>{
 const start=await api("/auth/register/begin",{name:$("account-name").value});const credential=await navigator.credentials.create({publicKey:optionsFromJSON(start.options)});
 await api("/auth/register/finish",{ceremony:start.ceremony,credential:publicCredential(credential,start.options)});session=await api("/session");show("unlock-view");toast("Passkey created. Unlock your vault to finish setup.");
});};
$("unlock").onclick=()=>action($("unlock"),async()=>{const {credential}=await freshPasskey();await unlockWith(credential);});
$("signout").onclick=()=>action($("signout"),async()=>{await api("/logout",{});if(session)localStorage.removeItem(cacheName());lock();if(worker){worker.terminate();worker=null;}});
for(const button of document.querySelectorAll("[data-tab]"))button.onclick=()=>{for(const b of document.querySelectorAll("[data-tab]"))b.classList.toggle("selected",b===button);for(const tab of ["identities","requests","settings"])$(tab+"-panel").hidden=tab!==button.dataset.tab;if(button.dataset.tab==="requests")refreshRequests();};
for(const button of document.querySelectorAll("[data-close]"))button.onclick=()=>$(button.dataset.close).close();
function render(){
 const list=$("identity-list");list.replaceChildren();$("identity-empty").hidden=!!vault.identities.length;
 for(const identity of vault.identities){const card=node("article",undefined,"identity-card"),glyph=node("div",identity.type==="ssh"?"⌘":identity.type==="bitcoin"?"₿":"◇","identity-glyph"),details=node("div",undefined,"identity-details"),title=node("h2",identity.name);title.append(node("span",identity.type+(identity.threshold?" · all owners":""),"badge"));details.append(title,node("p",identity.address||identity.publicKey));const copy=node("button","Copy","text-button");copy.onclick=()=>action(copy,async()=>{await navigator.clipboard.writeText(identity.type==="ssh"?identity.publicKey:identity.address||identity.publicKey);toast("Public identity copied");});card.append(glyph,details,copy);list.append(card);}
 $("device-list").replaceChildren(...vault.devices.map(d=>node("p",`${d.name} · ${d.role==="agent"?"Signing agent":"Requesting client"}`)));
 $("owner-list").replaceChildren(...vault.delegates.map(o=>node("p",o.name||o.id)));
 if(!vault.delegates.length)$("owner-list").append(node("p","No delegated owners yet.","fine-print"));
}
$("add-identity").onclick=()=>{$("identity-form").reset();setMode("generate");$("identity-dialog").showModal();};
function setMode(next){mode=next;for(const b of document.querySelectorAll("[data-mode]"))b.classList.toggle("selected",b.dataset.mode===mode);$("import-fields").hidden=mode!=="import";$("generation-note").hidden=mode==="import";$("save-identity").textContent=mode==="import"?"Encrypt and save identity":"Create identity";$("private-key").required=mode==="import";updateType();}
for(const b of document.querySelectorAll("[data-mode]"))b.onclick=()=>setMode(b.dataset.mode);
let providers;
async function updateType(){
 const type=$("identity-type").value,isKey=["ssh","ethereum","bitcoin"].includes(type);$("network-field").hidden=type!=="bitcoin";$("key-passphrase").hidden=type!=="ssh";document.querySelector('label[for="key-passphrase"]').hidden=type!=="ssh";
 $("credential-fields").hidden=isKey;$("import-fields").hidden=!isKey||mode!=="import";$("private-key").required=isKey&&mode==="import";$("generation-note").hidden=!isKey||mode==="import";
 for(const button of document.querySelectorAll("[data-mode]"))button.disabled=!isKey;
 if(!isKey){$("save-identity").textContent="Encrypt and save credentials";providers??=await work({action:"providers"});const fields=$("credential-fields");fields.replaceChildren();for(const f of providers[type].fields){const label=node("label",f.label),input=node("input");input.id="credential-"+f.name;label.htmlFor=input.id;input.required=f.required;input.type=f.secret?"password":"text";input.autocomplete="off";input.spellcheck=false;input.setAttribute("data-1p-ignore","");fields.append(label,input);}if(type==="payment-card")fields.append(node("p","CVVs stay on your own device and are excluded from cloud storage and backups.","fine-print"));}
}
$("identity-type").onchange=updateType;
$("identity-form").onsubmit=event=>{event.preventDefault();action(event.submitter,async()=>{
 const name=$("identity-name").value.trim(),type=$("identity-type").value;
 if(vault.identities.some(i=>i.name===name && i.type===type))throw new Error("An identity with this name and type already exists");
 if(mode==="generate" && type!=="ssh" && vault.delegates.length)throw new Error("Use a shared-key ceremony to include your delegated owners");
 const isKey=["ssh","ethereum","bitcoin"].includes(type);let key=$("private-key").value;if(!isKey){const fields={};for(const f of providers[type].fields)fields[f.name]=$("credential-"+f.name).value;key=JSON.stringify({provider:type,fields});}const identity=await work({action:isKey?mode:"import",name,type,network:type==="bitcoin"?$("identity-network").value:"",key,password:$("key-passphrase").value});
 await save({...vault,identities:[...vault.identities,identity]});$("identity-form").reset();$("identity-dialog").close();toast("Identity encrypted and saved");
});};
function beginBackup(isRestore){restoring=isRestore;restorePreview=null;$("backup-form").reset();$("restore-preview").replaceChildren();$("backup-title").textContent=isRestore?"Restore encrypted backup":"Download encrypted backup";$("backup-description").textContent=isRestore?"Enter the password used to encrypt this file. You can review its identities before saving.":"Choose a strong password. Keep it separately from the backup file.";$("confirm-password-field").hidden=isRestore;$("backup-submit").textContent=isRestore?"Decrypt and preview":"Encrypt and download";$("backup-password").autocomplete=isRestore?"current-password":"new-password";$("backup-dialog").showModal();}
$("backup").onclick=()=>beginBackup(false);$("restore").onclick=()=>$("backup-file").click();
$("backup-file").onchange=()=>action(null,async()=>{const file=$("backup-file").files[0];if(!file)return;if(file.size>12*1024*1024)throw new Error("Backup exceeds 12 MiB");backupFile=await file.text();$("backup-file").value="";beginBackup(true);});
function download(name,body){const href=URL.createObjectURL(new Blob([body],{type:"application/json"}));const a=node("a");a.href=href;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(href),1000);}
$("backup-form").onsubmit=event=>{event.preventDefault();action(event.submitter,async()=>{
 if(!restoring){const password=$("backup-password").value;if(password!==$("backup-password-confirm").value)throw new Error("The backup passwords do not match");const encrypted=await work({action:"backup-encrypt",password,data:JSON.stringify({version:1,identities:vault.identities})});download(`grexie-vault-backup-${new Date().toISOString().slice(0,10)}.json`,encrypted);$("backup-form").reset();$("backup-dialog").close();toast("Encrypted backup downloaded");return;}
 if(!restorePreview){
  const decoded=await work({action:"backup-decrypt",password:$("backup-password").value,data:backupFile});$("backup-password").value="";backupFile=null;restorePreview=[];
  const names=new Set(vault.identities.map(i=>i.type+"\0"+i.name));
  for(const identity of decoded.identities){const duplicate=vault.identities.some(i=>i.id===identity.id || ["ssh","ethereum","bitcoin"].includes(identity.type) && i.type===identity.type && i.network===identity.network && i.publicKey===identity.publicKey);let name=identity.name;let count=1;while(names.has(identity.type+"\0"+name)&&!duplicate){name=identity.name+` (restored ${count++})`;}
   $("restore-preview").append(node("div",duplicate?`${identity.name} — already present; will be skipped`:`${name} — ${identity.type}${identity.threshold?" (your share only)":""}`,"restore-row"));if(!duplicate){names.add(identity.type+"\0"+name);restorePreview.push({...identity,name,id:b64url(crypto.getRandomValues(new Uint8Array(24)))});}}
  $("backup-submit").textContent=`Restore ${restorePreview.length} identities`;$("backup-password").required=false;$("backup-password").hidden=true;document.querySelector('label[for="backup-password"]').hidden=true;return;
 }
 await save({...vault,identities:[...vault.identities,...restorePreview]});restorePreview=null;$("backup-dialog").close();toast("Backup restored; existing identities preserved");
});};
$("backup-dialog").addEventListener("close",()=>{restorePreview=null;backupFile=null;$("backup-form").reset();$("backup-password").hidden=false;$("backup-password").required=true;document.querySelector('label[for="backup-password"]').hidden=false;});

// Request display is built from signed device data and local decoders. Requester
// prose is displayed separately from the decoded transaction.
let selectedRequest;
$("review-dialog").addEventListener("close",()=>{selectedRequest=null;$("review-content").replaceChildren();});
async function refreshRequests(){if(!root)return;try{const result=await api("/requests");const requests=result.requests||[];$("request-count").textContent=requests.length?String(requests.length):"";$("request-list").replaceChildren();$("request-empty").hidden=!!requests.length;for(const request of requests){const card=node("article",undefined,"identity-card"),text=node("div",undefined,"identity-details");text.append(node("h2",request.session||"Access request"),node("p",request.reason||"Review this request"));const button=node("button","Review","button outline small");button.disabled=request.status==="pending"&&!request.receiver&&JSON.parse(new TextDecoder().decode(unb64(request.signed.payload))).managed===true;if(button.disabled)text.append(node("p","Waiting for the signing device","fine-print"));button.onclick=()=>action(button,()=>reviewRequest(request));card.append(text,button);$("request-list").append(card);}}catch(e){if(!String(e.message).includes("not found"))toast(e.message,true);}}
function addFields(container,fields){const dl=node("dl",undefined,"review-fields");for(const field of fields){const row=node("div");row.append(node("dt",field.label),node("dd",field.value));dl.append(row);}container.append(dl);}
function addCall(container,call){const box=node("div",undefined,"decoded-call");box.append(node("h3",call.method));addFields(box,call.arguments||[]);if(call.warning)box.append(node("p",call.warning,"warning"));for(const child of call.children||[])addCall(box,child);container.append(box);}
async function reviewRequest(request){
 const generation=epoch;
 const device=vault.devices.find(d=>d.id===request.deviceId);if(!device)throw new Error("This device is not pinned in your vault. Pair it before approving.");
 const spec=await verify(device.publicKey,"request",request.signed);if(spec.id!==request.id||spec.deviceId!==device.id||Date.parse(spec.expiresAt)<=Date.now()&&request.status==="pending")throw new Error("Request identity mismatch");await work({action:"validate-request",data:JSON.stringify(spec)});selectedRequest={request,spec,device};$("approve-request").hidden=request.status!=="pending";$("decline-request").textContent=request.status==="approved"?"Revoke access":"Decline";const content=$("review-content");content.replaceChildren(node("p",spec.reason,"request-reason"));
 if(spec.kind==="keychain-import"){const intent=JSON.parse(new TextDecoder().decode(unb64(spec.payload)));content.append(node("h2","Import a website password"));addFields(content,[{label:"Source",value:intent.source},{label:"Website",value:intent.origin},{label:"Account",value:intent.username||"One matching account"}]);content.append(node("p","Allow this device to read the selected login through macOS authorization or your exported file. You can review the account before it is saved.","fine-print"));}else if(spec.kind==="import"){
  const box=JSON.parse(new TextDecoder().decode(unb64(spec.payload)));const record=await openEnvelope(root,`import:${device.id}`,box);if(generation!==epoch)throw new Error("Vault locked");const checked=await work({action:"validate",data:JSON.stringify(record)});if(checked.name!==spec.identity||checked.type!==spec.identityType)throw new Error("Imported identity does not match the request");selectedRequest.imported=checked;content.append(node("h2","Import credentials"));addFields(content,[{label:"Identity",value:checked.name},{label:"Type",value:checked.type},{label:"Account",value:checked.address}]);content.append(node("p","Only encrypted data will be saved. Your existing local credentials will remain in place.","fine-print"));
 }else if(spec.kind==="credentials"||spec.kind==="api"||spec.kind==="autofill"){
  const invocation=JSON.parse(new TextDecoder().decode(unb64(spec.payload)));content.append(node("h2",spec.kind==="autofill"?"Autofill website":spec.kind==="api"?"Use provider API":"Allow command access"));addFields(content,[{label:"Provider",value:invocation.provider},{label:"Identity",value:spec.identity||"Only matching identity"},{label:"Duration",value:`${spec.duration} seconds`}]);if(spec.kind==="api")addFields(content,[{label:"Method",value:invocation.method},{label:"Path",value:invocation.path},{label:"Body SHA-256",value:invocation.bodyHash}]);if(invocation.command)content.append(node("pre",JSON.stringify([invocation.command,...invocation.arguments||[]])));if(invocation.origin)addFields(content,[{label:"Website",value:invocation.origin},{label:"Merchant",value:invocation.merchant||invocation.origin},{label:"Amount",value:invocation.amount?`${invocation.amount} ${invocation.currency}`:"Not supplied — autofill only"}]);content.append(node("p",spec.kind==="credentials"?"The command receives this credential and may retain it. Revocation stops further Vault access; it does not invalidate a copied provider token.":spec.kind==="autofill"?"The selected website receives these values. Vault fills fields without submitting the form.":"The local device receives this credential to send the API request. A compromised device could retain it or use it elsewhere. Revocation stops further Vault access.","warning"));if(invocation.profileHash){const details=node("details");details.append(node("summary","Installed provider profile"),node("code",invocation.profileHash));content.append(details);}
 }else if(spec.kind==="ethereum"){
  const raw=new TextDecoder().decode(unb64(spec.payload));const review=await work({action:"review-ethereum",data:raw});content.append(node("h2",review.title));addFields(content,review.fields);
  const tx=JSON.parse(raw);if(tx.to && (tx.data||tx.input||"0x").length>=10){
   const callContainer=node("div");content.prepend(callContainer);
   try{const found=await verifiedABIs(tx.chainId,tx.to);if(generation!==epoch)throw new Error("Vault locked");let decoded=false;for(const contract of found.contracts){try{const call=await work({action:"decode-abi",abi:JSON.stringify(contract.abi),data:tx.data||tx.input});addCall(callContainer,call);decoded=true;break;}catch{}}
    if(!decoded)callContainer.append(node("p","This method could not be decoded with the available ABI.","warning"));for(const warning of found.warnings)callContainer.append(node("p",warning,"warning"));const details=node("details"),summary=node("summary","Contract details");details.append(summary);for(const contract of found.contracts){const link=node("a",contract.name||contract.address);link.href=contract.source;link.target="_blank";link.rel="noopener noreferrer";const button=node("button","Download ABI","text-button");button.onclick=()=>downloadABI(tx.chainId,contract);details.append(link,node("br"),button,node("br"));}content.append(details);
   }catch{callContainer.append(node("p","Contract details are unavailable. Review the selector and full calldata before approving.","warning"));}
  }
  for(const warning of review.warnings)content.append(node("p",warning,"warning"));const details=node("details");details.append(node("summary","Raw transaction"),node("pre",raw));content.append(details);
 }else if(spec.kind==="bitcoin"){
  const identity=vault.identities.find(i=>i.name===spec.identity&&i.type==="bitcoin");const review=await work({action:"review-bitcoin",data:spec.payload,network:spec.network,publicKey:identity?.publicKey||""});content.append(node("h2",review.title));addFields(content,review.fields);for(const warning of review.warnings)content.append(node("p",warning,"warning"));
 }else{content.append(node("h2",spec.kind==="create"?"Create a new identity":"Allow access"));addFields(content,[{label:"Identity",value:spec.identity},{label:"Type",value:spec.identityType},{label:"Duration",value:`${spec.duration} seconds`}]);}
 if(generation!==epoch||!root)throw new Error("Vault locked; review cancelled");$("review-dialog").showModal();
}
$("decline-request").onclick=()=>action($("decline-request"),async()=>{await api(`/requests/${selectedRequest.request.id}/${selectedRequest.request.status==="approved"?"revoke":"decline"}`,{});$("review-dialog").close();refreshRequests();});
$("approve-request").onclick=()=>action($("approve-request"),async()=>{
 const {credential,verification}=await freshPasskey("approve:"+selectedRequest.spec.id);const prf=credential.getClientExtensionResults().prf?.results?.first;if(prf)new Uint8Array(prf).fill(0);
 const {request,spec,device}=selectedRequest;
 if(["create","import","lookup","keychain-import"].includes(spec.kind)){
  let result;
  if(spec.kind==="keychain-import"){result={approved:true};}else if(spec.kind==="lookup"){
   result=vault.identities.filter(i=>(!spec.identity||i.name===spec.identity)&&(!spec.identityType||i.type===spec.identityType)).map(({secret,...publicIdentity})=>publicIdentity);
  }else{
   if(spec.kind==="create"&&vault.delegates.length&&spec.identityType!=="ssh")throw new Error("Every delegated owner must join shared-key generation");
   if(vault.identities.some(i=>i.name===spec.identity&&i.type===spec.identityType))throw new Error("This identity name already exists; choose a new name to preserve the existing identity");
   const identity=spec.kind==="import"?selectedRequest.imported:await work({action:"generate",name:spec.identity,type:spec.identityType,network:spec.network||""});
   if(!identity)throw new Error("Review the identity before importing");await save({...vault,identities:[...vault.identities,identity]});const {secret,...publicIdentity}=identity;result=publicIdentity;
  }
  const response=await sign(root,"response",{requestId:spec.id,requestHash:await digest(unb64(request.signed.payload)),result:b64(bytes(JSON.stringify(result))),expiresAt:new Date(Date.now()+120000).toISOString()});await api(`/requests/${spec.id}/complete`,{response,verification});
 }else{
  const matches=vault.identities.filter(i=>(!spec.identity||i.name===spec.identity)&&i.type===spec.identityType&&(spec.identityType!=="credentials"||i.network===spec.network));if(matches.length>1)throw new Error("More than one identity matches; request one by name");const identity=matches[0];if(!identity)throw new Error("The selected identity does not exist");if(identity.threshold)throw new Error("This identity requires every delegated owner");
  const agent=vault.devices.find(d=>d.id===spec.agentId);if(!agent||(spec.managed&&agent.role!=="agent")||!request.receiver)throw new Error("The signing device is not ready or is not pinned");const receiver=await verify(agent.publicKey,"receiver",request.receiver);const requestHash=await digest(unb64(request.signed.payload));if(receiver.requestId!==spec.id || receiver.requestHash!==requestHash || Date.parse(receiver.expiresAt)<=Date.now())throw new Error("Device receiver expired or does not match this request");
  const receiverHash=await digest(unb64(request.receiver.payload)),expiresAt=new Date(Math.min(Date.now()+spec.duration*1000,Date.parse(receiver.expiresAt))).toISOString();
  const approval=await sign(root,"approval",{requestId:spec.id,requestHash,receiverHash,identityId:identity.id,identityType:identity.type,publicKey:identity.publicKey,secret:identity.secret,expiresAt,requesterPublic:device.publicKey});
  const authorization=await sign(root,"authorization",{requestId:spec.id,requestHash,receiverHash,agentPublic:agent.publicKey,publicKey:identity.publicKey,expiresAt});
  const box=await envelope(receiver.publicKey,`approval:${spec.id}`,approval);await api(`/requests/${spec.id}/approve`,{box,verification,authorization});
 }
 $("review-dialog").close();toast("Request approved");refreshRequests();
});
$("pair-code").addEventListener("input",()=>{
 const preview=$("pair-preview");preview.replaceChildren();try{const input=JSON.parse(new TextDecoder().decode(unb64($("pair-code").value.trim()))),d=input.device;preview.append(node("p",`${d.name} · ${d.role==="agent"?"Signing agent":"Requesting client"}`),node("code",input.fingerprint));if(d.role==="agent")preview.append(node("p","This device will receive private keys when you approve signing access. Only connect a machine you control.","warning"));}catch{}
});
$("pair-form").onsubmit=event=>{event.preventDefault();action(event.submitter,async()=>{
 const input=JSON.parse(new TextDecoder().decode(unb64($("pair-code").value.trim())));if(input.version!==1||!input.device||!input.secret)throw new Error("Invalid pairing code");const device=input.device;
 if(!["client","agent"].includes(device.role))throw new Error("Invalid device role");
 if(await digest(unb64(device.publicKey))!==input.fingerprint)throw new Error("Pairing code fingerprint mismatch");
 const {verification}=await freshPasskey("pair:"+device.id);const pairing={deviceId:device.id,ownerId:session.userId,ownerPublic:root.signingPublic,ownerBoxPublic:root.boxPublic};const payload=bytes(JSON.stringify(pairing)),prefix=bytes("grexie-vault/pair/v1\0"),message=new Uint8Array(prefix.length+payload.length);message.set(prefix);message.set(payload,prefix.length);const key=await crypto.subtle.importKey("raw",unb64(input.secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);pairing.mac=b64(await crypto.subtle.sign("HMAC",key,message));
 const box=await envelope(device.boxPublic,`pair:${device.id}`,pairing);await api("/devices/pair",{deviceId:device.id,pairingHash:await digest(unb64(input.secret)),box,verification});await save({...vault,devices:[...vault.devices.filter(d=>d.id!==device.id),device]});$("pair-code").value="";$("pair-preview").replaceChildren();toast("Device paired and pinned");
});};
$("add-owner").onclick=()=>toast("Owner invitations will be available with the shared-key ceremony.");
const serviceWorker="serviceWorker" in navigator?navigator.serviceWorker.register("/sw.js"):null;
$("notifications").onclick=()=>action($("notifications"),async()=>{
 if(!serviceWorker || !("PushManager" in window))throw new Error("Install Vault on your Home Screen to receive notifications on this device");
 const permission=await Notification.requestPermission();if(permission!=="granted")throw new Error("Notifications were not permitted. You can enable them in device settings.");
 await serviceWorker;const registration=await navigator.serviceWorker.ready;const config=await api("/push/key");const subscription=await registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:unb64(config.publicKey)});await api("/push/subscribe",subscription.toJSON());toast("Notifications enabled on this device");
});
try{session=await api("/session");show("unlock-view");await rehydrate();}catch{show("auth-view");}
setInterval(()=>{if(root&&!$("requests-panel").hidden)refreshRequests();},2000);
