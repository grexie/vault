// Runs in an isolated Chrome world (or Safari's Apple Events JavaScript).
// Inspection returns field roles only: never existing field values.
function vaultPage(action, expected, values) {
 const origin=location.origin;
 if(location.protocol!=="https:" && !["http://127.0.0.1","http://localhost"].some(p=>origin===p||origin.startsWith(p+":")))throw new Error("HTTPS required");
 const tokenName="__grexieVaultDocumentV1";
 if(!globalThis[tokenName])Object.defineProperty(globalThis,tokenName,{value:crypto.randomUUID(),writable:false,configurable:false});
 const visible=input=>{const r=input.getBoundingClientRect(),s=getComputedStyle(input);return r.width>0&&r.height>0&&s.display!=="none"&&s.visibility!=="hidden"&&s.opacity!=="0"&&!input.disabled&&!input.readOnly;};
 const inputs=[...document.querySelectorAll("input")].filter(visible);
 const role=input=>{
  const tokens=input.autocomplete.toLowerCase().split(/\s+/),last=tokens.at(-1);
  const known={username:"username","current-password":"password","cc-name":"cardholder","cc-number":"number","cc-exp-month":"expiryMonth","cc-exp-year":"expiryYear","cc-exp":"expiry","cc-csc":"cvv"};
  if(known[last])return known[last];if(last==="new-password"||last==="one-time-code")return null;
  if(input.type==="password")return "password";
  if(input.type==="email")return "username";
  return null;
 };
 const fields=inputs.map(input=>({input,role:role(input)})).filter(f=>f.role);
 if(action==="inspect")return {origin,documentToken:globalThis[tokenName],fields:fields.map(f=>f.role)};
 if(action!=="fill"||origin!==expected.origin||globalThis[tokenName]!==expected.documentToken)throw new Error("Page changed after approval");
 const updates=[];
 for(const [key,value] of Object.entries(values)){
  if(typeof value!=="string"||value.length>32768)throw new Error("Invalid field value");
  const found=fields.filter(f=>f.role===key);
  if(found.length>1)throw new Error("Ambiguous fields; choose a specific frame or form");
  if(found.length===1)updates.push({input:found[0].input,value});
 }
 if(updates.length===0)throw new Error("No supported visible fields; use standard autocomplete attributes");
 // Validate every target before touching the first input. No clicks, form
 // submission, navigation, page-supplied selectors, or arbitrary JS from CLI.
 const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value").set;
 for(const {input,value} of updates){setter.call(input,value);input.dispatchEvent(new Event("input",{bubbles:true}));input.dispatchEvent(new Event("change",{bubbles:true}));}
 return {filled:updates.length,submitted:false};
}
