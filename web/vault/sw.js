self.addEventListener("install",()=>self.skipWaiting());
self.addEventListener("activate",event=>event.waitUntil(self.clients.claim()));
// Authentication, encrypted identities and API responses never enter a worker cache.
self.addEventListener("push",event=>{let data={};try{data=event.data?.json()||{};}catch{}event.waitUntil(self.registration.showNotification("Vault needs your approval",{body:"Open Vault to review a request from your device.",icon:"/icon-192.png",badge:"/icon-192.png",tag:typeof data.id==="string"?data.id:"vault-request",data:{url:"/app/#requests"}}));});
self.addEventListener("notificationclick",event=>{event.notification.close();event.waitUntil(self.clients.matchAll({type:"window",includeUncontrolled:true}).then(async clients=>{for(const client of clients){if(new URL(client.url).origin===self.location.origin){await client.focus();client.postMessage({type:"show-requests"});return;}}await self.clients.openWindow("/app/#requests");}));});
