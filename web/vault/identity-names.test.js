import test from "node:test";
import assert from "node:assert/strict";
import {restoredIdentityName} from "./identity-names.js";

test("restore conflict names fit the identity byte limit",()=>{
 const encoder=new TextEncoder();
 for(const name of ["a".repeat(80),"😀".repeat(20),"é".repeat(40)]){
  const first=restoredIdentityName(name,1),second=restoredIdentityName(name,2);
  assert(encoder.encode(first).length<=80);
  assert.equal(new TextDecoder("utf-8",{fatal:true}).decode(encoder.encode(first)),first);
  assert(first.endsWith(" (restored 1)"));
  assert.notEqual(first,second);
 }
 assert.equal(restoredIdentityName("Work",1),"Work (restored 1)");
});
