import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import vm from "node:vm";

const source=await readFile(new URL("./sw.js",import.meta.url),"utf8");
async function clickWith(paths){
 const handlers=new Map(),focused=[],messages=[],opened=[];let completion;
 const self={location:{origin:"https://vault.example"},addEventListener:(name,fn)=>handlers.set(name,fn),clients:{matchAll:async()=>paths.map(path=>({url:"https://vault.example"+path,focus:async()=>focused.push(path),postMessage:message=>messages.push({path,type:message.type})})),openWindow:async path=>opened.push(path)}};
 vm.runInNewContext(source,{self,URL});
 handlers.get("notificationclick")({notification:{close(){}},waitUntil:promise=>completion=promise});await completion;
 return {focused,messages,opened};
}
test("notification focuses the app, not a marketing or documentation window",async()=>{
 assert.deepEqual(await clickWith(["/","/guide.html","/app/"]),{focused:["/app/"],messages:[{path:"/app/",type:"show-requests"}],opened:[]});
});
test("notification opens Requests when only other site pages are open",async()=>{
 assert.deepEqual(await clickWith(["/","/architecture.html"]),{focused:[],messages:[],opened:["/app/#requests"]});
});
