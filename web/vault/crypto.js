const encoder = new TextEncoder();
export const bytes = (value) => encoder.encode(value);
export function b64(value) {const b=new Uint8Array(value);let s="";for(let i=0;i<b.length;i+=32768)s+=String.fromCharCode(...b.subarray(i,i+32768));return btoa(s);}
export function unb64(value) {return Uint8Array.from(atob(value.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));}
export const b64url = (value) => b64(value).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
export async function seal(raw,context,value) {
 const key=await crypto.subtle.importKey("raw",raw,"AES-GCM",false,["encrypt"]),iv=crypto.getRandomValues(new Uint8Array(12));
 const plain=bytes(JSON.stringify(value));
 try {const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:bytes(context)},key,plain);return {iv:b64(iv),ciphertext:b64(cipher)};}finally{plain.fill(0);}
}
export async function open(raw,context,box) {
 if(unb64(box.iv).length!==12)throw new Error("Invalid encrypted record");
 const key=await crypto.subtle.importKey("raw",raw,"AES-GCM",false,["decrypt"]);
 const plain=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(box.iv),additionalData:bytes(context)},key,unb64(box.ciphertext)));
 try{return JSON.parse(new TextDecoder().decode(plain));}finally{plain.fill(0);}
}
export async function prfKey(prf,user,credential) {
 if(!prf || prf.byteLength!==32)throw new Error("Your passkey provider did not supply PRF encryption. Choose a supported device keychain.");
 const material=await crypto.subtle.importKey("raw",prf,"HKDF",false,["deriveBits"]);
 return new Uint8Array(await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:bytes(credential),info:bytes("grexie-vault/prf/v1:"+user)},material,256));
}
export async function newRoot() {
 const signing=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const box=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
 return {key:b64(crypto.getRandomValues(new Uint8Array(32))),signingPrivate:await crypto.subtle.exportKey("jwk",signing.privateKey),signingPublic:b64(await crypto.subtle.exportKey("raw",signing.publicKey)),boxPrivate:await crypto.subtle.exportKey("jwk",box.privateKey),boxPublic:b64(await crypto.subtle.exportKey("raw",box.publicKey))};
}
export async function sign(root,domain,value) {
 const key=await crypto.subtle.importKey("jwk",root.signingPrivate,{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
 const payload=bytes(JSON.stringify(value));const prefix=bytes("grexie-vault/"+domain+"/v1\0"),message=new Uint8Array(prefix.length+payload.length);message.set(prefix);message.set(payload,prefix.length);
 return {payload:b64(payload),signature:b64(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key,message))};
}
export async function verify(publicKey,domain,signed) {
 const payload=unb64(signed.payload),prefix=bytes("grexie-vault/"+domain+"/v1\0"),message=new Uint8Array(prefix.length+payload.length);message.set(prefix);message.set(payload,prefix.length);
 const key=await crypto.subtle.importKey("raw",unb64(publicKey),{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
 if(!await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,unb64(signed.signature),message))throw new Error("Device signature did not verify");
 return JSON.parse(new TextDecoder().decode(payload));
}
export async function envelope(publicKey,context,value) {
 const receiver=await crypto.subtle.importKey("raw",unb64(publicKey),{name:"ECDH",namedCurve:"P-256"},false,[]);
 const ephemeral=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
 const secret=await crypto.subtle.deriveBits({name:"ECDH",public:receiver},ephemeral.privateKey,256),salt=crypto.getRandomValues(new Uint8Array(32)),iv=crypto.getRandomValues(new Uint8Array(12));
 const material=await crypto.subtle.importKey("raw",secret,"HKDF",false,["deriveKey"]);
 const key=await crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt,info:bytes("grexie-vault/box/v1\0"+context)},material,{name:"AES-GCM",length:256},false,["encrypt"]);
 const plain=bytes(JSON.stringify(value));try{return {publicKey:b64(await crypto.subtle.exportKey("raw",ephemeral.publicKey)),salt:b64(salt),iv:b64(iv),ciphertext:b64(await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:bytes(context)},key,plain))};}finally{plain.fill(0);new Uint8Array(secret).fill(0);}
}
export async function digest(value) {return [...new Uint8Array(await crypto.subtle.digest("SHA-256",value))].map(n=>n.toString(16).padStart(2,"0")).join("");}
export async function openEnvelope(root,context,box) {
 const peer=await crypto.subtle.importKey("raw",unb64(box.publicKey),{name:"ECDH",namedCurve:"P-256"},false,[]),privateKey=await crypto.subtle.importKey("jwk",root.boxPrivate,{name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]);
 const secret=await crypto.subtle.deriveBits({name:"ECDH",public:peer},privateKey,256),material=await crypto.subtle.importKey("raw",secret,"HKDF",false,["deriveKey"]);
 const key=await crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt:unb64(box.salt),info:bytes("grexie-vault/box/v1\0"+context)},material,{name:"AES-GCM",length:256},false,["decrypt"]);
 try{const plain=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(box.iv),additionalData:bytes(context)},key,unb64(box.ciphertext)));try{return JSON.parse(new TextDecoder().decode(plain));}finally{plain.fill(0);}}finally{new Uint8Array(secret).fill(0);}
}
