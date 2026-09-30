export function formatDuration(seconds) {
 const total=Math.max(0,Math.ceil(Number(seconds)||0));
 const hours=Math.floor(total/3600),minutes=Math.floor(total%3600/60),remaining=total%60;
 return `${hours?hours+"h":""}${minutes?minutes+"m":""}${remaining?remaining+"s":""}`||"0s";
}

export function requestTiming(request,now=Date.now()) {
 let deadline=request.status==="pending"?(request.approvalDeadline||request.expiresAt):request.expiresAt;
 // The browser-signed lease can end slightly before the relay's record TTL.
 if(request.status==="approved"&&request.authorization?.payload){
  try{const authorization=JSON.parse(atob(request.authorization.payload));if(authorization.requestId===request.id&&authorization.expiresAt)deadline=authorization.expiresAt;}catch{}
 }
 const end=Date.parse(deadline),known=Number.isFinite(end),expired=known&&end<=now;
 const status=expired?"expired":request.status;
 const label=status==="pending"?"Pending approval":status==="approved"?"Approved":status==="expired"?"Expired":"Unavailable";
 const countdown=!known?"Expiry unavailable":expired?"Expired":`${status==="approved"?"Lease expires":"Expires"} in ${formatDuration((end-now)/1000)}`;
 return {status,label,countdown,deadline:known?end:null};
}

export function createRequestStatus(request) {
 const timing=requestTiming(request),row=document.createElement("div");
 row.className="request-status";row.dataset.requestStatus=request.status;
 if(timing.deadline!==null)row.dataset.deadline=String(timing.deadline);
 const badge=document.createElement("span"),countdown=document.createElement("span");
 badge.className="request-badge";countdown.className="request-countdown";
 row.append(badge,countdown);updateRequestStatus(row);
 return row;
}

export function updateRequestStatus(row,now=Date.now()) {
 const deadline=Number(row.dataset.deadline);
 const timing=requestTiming({status:row.dataset.requestStatus,expiresAt:row.dataset.deadline===undefined?undefined:new Date(deadline).toISOString()},now);
 row.dataset.state=timing.status;
 row.querySelector(".request-badge").textContent=timing.label;
 const countdown=row.querySelector(".request-countdown");
 countdown.textContent=timing.countdown;
 if(timing.deadline!==null)countdown.title=new Date(timing.deadline).toLocaleString();
}

export function updateRequestCountdowns(scope=document,now=Date.now()) {
 for(const row of scope.querySelectorAll("[data-request-status]"))updateRequestStatus(row,now);
}
