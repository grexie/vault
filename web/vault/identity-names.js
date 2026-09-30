// Identity names are limited to 80 UTF-8 bytes by the key parser and broker.
export function restoredIdentityName(original, count) {
 if(!Number.isSafeInteger(count)||count<1)throw new Error("Invalid restore suffix");
 const suffix=` (restored ${count})`,characters=Array.from(original),encoder=new TextEncoder();
 while(encoder.encode(characters.join("")+suffix).length>80)characters.pop();
 return characters.join("")+suffix;
}
