// Public messages and retained diagnostics are allowlisted; never expose raw exceptions.
export function quotaDetails(error,{member=false,now,leaseUntil,timeBudget=false}){
  const dayReset=(Math.floor(now/86400)+1)*86400;
  const date=new Date(now*1000),monthReset=Date.UTC(date.getUTCFullYear(),date.getUTCMonth()+1,1)/1000;
  const definitions=[
    {code:'GLOBAL_DAILY_LIMIT',message:'All 5 shared browser starts for today have been used.',retryAt:dayReset},
    {code:'GLOBAL_MONTHLY_LIMIT',message:'All 100 shared browser starts for this month have been used.',retryAt:monthReset},
    ...(!member?[{code:'NETWORK_DAILY_LIMIT',message:'Your public network has used its 2 browser starts for today.',retryAt:dayReset}]:[]),
    {code:'SESSION_BUSY',message:'The single shared browser slot is occupied or completing its startup reservation.',retryAt:Math.max(now+1,Number.isFinite(leaseUntil)?leaseUntil:now+120)}
  ];
  if(timeBudget)definitions.push(null,
    {code:'GLOBAL_DAILY_TIME_LIMIT',message:'The shared daily browser-time budget cannot fit this session.',retryAt:dayReset},
    {code:'GLOBAL_MONTHLY_TIME_LIMIT',message:'The shared monthly browser-time budget cannot fit this session.',retryAt:monthReset},
    {code:'BUDGET_CHANGED',message:'Budget settings changed during admission. Refresh before trying again.',retryAt:now+1});
  const reasons=definitions.filter((d,i)=>d&&error.CancellationReasons?.[i]?.Code==='ConditionalCheckFailed');
  if(!reasons.length)return {code:'ADMISSION_CONFLICT',reasons:[],retryAt:now+120,message:'The browser reservation conflicted with another request. No browser was started. Please try again in two minutes.'};
  const retryAt=Math.max(...reasons.map(r=>r.retryAt));
  const reset=new Date(retryAt*1000).toISOString().replace('T',' ').replace('.000Z',' UTC');
  return {code:reasons[0].code,reasons,retryAt,message:reasons.map(r=>r.message).join(' ')+` Try again after ${reset}. Availability is shared and is not guaranteed. No browser was started.`};
}
export function failureDetails(error,stage){
  const text=String(error?.message||'');
  if(/ERR_NAME_NOT_RESOLVED|ENOTFOUND|No public A or AAAA/i.test(text))return {code:'DNS_NOT_FOUND',message:'The website hostname could not be resolved.'};
  if(/restricted address|private answer|Only public internet/i.test(text))return {code:'TARGET_RESTRICTED',message:'The website resolves to a restricted network address and cannot be opened.'};
  if(/ERR_CERT|CERT_HAS_EXPIRED|certificate/i.test(text))return {code:'TLS_ERROR',message:'The website failed the browser certificate/security check.'};
  if(/ERR_CONNECTION_REFUSED|ECONNREFUSED/i.test(text))return {code:'CONNECTION_REFUSED',message:'The connection was refused.'};
  if(error?.name==='TimeoutError'||/timed? ?out|ETIMEDOUT|ERR_CONNECTION_TIMED_OUT/i.test(text))return {code:'TIMEOUT',message:`The ${stage==='resolve'?'DNS lookup':stage==='start'?'browser startup':'browser operation'} timed out.`};
  if(/Throttling|TooManyRequests|ServiceQuotaExceeded/.test(error?.name||''))return {code:'PROVIDER_LIMIT',message:'The browser provider is temporarily limiting requests.'};
  if(error?.name==='AccessDeniedException')return {code:'SERVICE_PERMISSION_ERROR',message:'The service could not access a required resource. The administrator can review this error.'};
  return {code:{resolve:'DNS_LOOKUP_FAILED',start:'BROWSER_START_FAILED',save:'SESSION_SAVE_FAILED',sign:'VIEWER_AUTH_FAILED',open:'PAGE_OPEN_FAILED',capture:'CAPTURE_FAILED',stop:'STOP_FAILED'}[stage]||'SERVICE_ERROR',message:{resolve:'The DNS lookup failed.',start:'The remote browser could not start.',save:'The session could not be saved.',sign:'The live viewer could not be authorized.',open:'The submitted page could not be opened.',capture:'The page could not be captured.',stop:'The browser stop could not be confirmed.'}[stage]||'The service operation failed.'};
}
