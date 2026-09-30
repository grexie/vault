import test from "node:test";
import assert from "node:assert/strict";
import {formatDuration,requestTiming} from "./request-time.js";

test("durations use compact hours, minutes and seconds",()=>{
 for(const [seconds,expected]of [[3933,"1h5m33s"],[320,"5m20s"],[300,"5m"],[3600,"1h"],[172800,"48h"],[0,"0s"],[-1,"0s"],[0.1,"1s"]])assert.equal(formatDuration(seconds),expected);
});
test("pending countdown uses approval deadline, approved uses signed lease deadline",()=>{
 const now=Date.parse("2026-09-30T05:00:00Z"),request={id:"fixture",status:"pending",approvalDeadline:new Date(now+320000).toISOString(),expiresAt:new Date(now+999000).toISOString()};
 assert.equal(requestTiming(request,now).label,"Pending approval");
 assert.equal(requestTiming(request,now).countdown,"Expires in 5m20s");
 request.status="approved";
 request.authorization={payload:btoa(JSON.stringify({requestId:"fixture",expiresAt:new Date(now+3933000).toISOString()}))};
 assert.equal(requestTiming(request,now).label,"Approved");
 assert.equal(requestTiming(request,now).countdown,"Lease expires in 1h5m33s");
 assert.equal(requestTiming(request,now+3933000).status,"expired");
 assert.equal(requestTiming(request,now+4000000).countdown,"Expired");
});
test("missing or malformed expiry never produces a misleading countdown",()=>{
 assert.equal(requestTiming({status:"approved",expiresAt:"invalid"}).countdown,"Expiry unavailable");
 assert.equal(requestTiming({id:"one",status:"approved",expiresAt:"invalid",authorization:{payload:btoa(JSON.stringify({requestId:"two",expiresAt:new Date().toISOString()}))}}).deadline,null);
});
