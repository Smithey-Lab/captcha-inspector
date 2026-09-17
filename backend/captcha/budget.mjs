export const DEFAULT_BUDGET=Object.freeze({dailySeconds:300,monthlySeconds:6000,maxSessionSeconds:60,revision:0});
export function validateBudget(value){
  const result={};
  for(const [key,max] of [['dailySeconds',86400],['monthlySeconds',2678400],['maxSessionSeconds',28800]]){
    const n=value?.[key];
    if(!Number.isInteger(n)||n<60||n>max)throw new Error(`${key} must be a whole number from 60 to ${max}.`);
    result[key]=n;
  }
  if(result.maxSessionSeconds>result.dailySeconds||result.dailySeconds>result.monthlySeconds)throw new Error('Session duration must fit the daily budget, which must fit the monthly budget.');
  return result;
}
export function storedBudget(record){return record?{...validateBudget(record),revision:record.revision}: {...DEFAULT_BUDGET};}
export function durationFor({member,requested,maxSeconds=60,budget}){
  const seconds=member?(requested??60):60;
  if(!Number.isInteger(seconds)||seconds<60||seconds>28800||seconds>budget.maxSessionSeconds||seconds>maxSeconds)throw new Error('Choose a finite session duration within your permission and the shared maximum.');
  return seconds;
}
export function budgetItems({table,now,seconds,budget}){
  const day=Math.floor(now/86400),month=new Date(now*1000).toISOString().slice(0,7);
  const counter=(id,limit,expires)=>({Update:{TableName:table,Key:{id},UpdateExpression:'SET expires = :expires ADD #n :seconds',ConditionExpression:'attribute_not_exists(#n) OR #n <= :remaining',ExpressionAttributeNames:{'#n':'count'},ExpressionAttributeValues:{':expires':expires,':seconds':seconds,':remaining':limit-seconds}}});
  return [counter(`sandbox:seconds:day:${day}`,budget.dailySeconds,now+172800),counter(`sandbox:seconds:month:${month}`,budget.monthlySeconds,now+35*86400),{ConditionCheck:{TableName:table,Key:{id:'sandbox:settings'},ConditionExpression:budget.revision?'revision = :revision':'attribute_not_exists(id)',...(budget.revision?{ExpressionAttributeValues:{':revision':budget.revision}}:{})}}];
}
