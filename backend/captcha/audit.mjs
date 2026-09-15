import {createHash} from 'node:crypto';
import {TransactWriteCommand,UpdateCommand} from '@aws-sdk/lib-dynamodb';
const hash=value=>createHash('sha256').update(value).digest('hex');
export function submissionTransaction({table,key,target,network,now,memberSub}){
  const url=new URL(target),day=Math.floor(now/86400);
  return {TransactItems:[
    {Update:{TableName:table,Key:{id:`sandbox:audit-limit:${day}`},UpdateExpression:'SET expires = :ttl ADD #n :one',ConditionExpression:'attribute_not_exists(#n) OR #n < :max',ExpressionAttributeNames:{'#n':'count'},ExpressionAttributeValues:{':ttl':now+172800,':one':1,':max':1000}}},
    {Put:{TableName:table,Item:{id:key.replace('sandbox:session:','sandbox:audit:'),tool:'captcha',actorType:memberSub?'member':'public',...(memberSub?{actorSub:memberSub}:{}),submittedUrl:url.origin+url.pathname,queryKeys:[...new Set(url.searchParams.keys())].slice(0,30),fragmentPresent:!!url.hash,sourceHash:hash(`${day}:${network}`),createdAt:now,expires:now+30*86400,eventCount:1,events:[{at:now,type:'submitted'}]},ConditionExpression:'attribute_not_exists(id)'}}
  ]};
}
export function auditWriter(db,table,now){
  return {
    submit:args=>db.send(new TransactWriteCommand(submissionTransaction({...args,table}))),
    append:(key,type,details={})=>db.send(new UpdateCommand({TableName:table,Key:{id:key.replace('sandbox:session:','sandbox:audit:')},UpdateExpression:'SET events = list_append(events, :event) ADD eventCount :one',ConditionExpression:'attribute_exists(id) AND eventCount < :max',ExpressionAttributeValues:{':event':[{at:now(),type,...details}],':one':1,':max':16}}))
  };
}
