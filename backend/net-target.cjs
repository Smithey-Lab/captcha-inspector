'use strict';
const {isIP,BlockList}=require('node:net');
const {Resolver}=require('node:dns').promises;
// Conservative public-address policy. IPv6 transition mechanisms are excluded.
const blocked = new BlockList();
for (const [address, prefix] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.88.99.0',24],['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]]) blocked.addSubnet(address,prefix,'ipv4');
const global6 = new BlockList(); global6.addSubnet('2000::',3,'ipv6');
for (const [address,prefix] of [['2001::',23],['2001:db8::',32],['2002::',16],['3fff::',20]]) blocked.addSubnet(address,prefix,'ipv6');
function publicIP(address) {
  const family=isIP(address);
  return family===4 ? !blocked.check(address,'ipv4') : family===6 && global6.check(address,'ipv6') && !blocked.check(address,'ipv6');
}
function parseTarget(value) {
  // Reject control characters in submitted targets.
  // eslint-disable-next-line no-control-regex
  if (typeof value!=='string' || value.length>2048 || /[\s\\\x00-\x1f]/.test(value.trim())) throw new Error('Enter a public hostname, IP address, or HTTP(S) URL.');
  let raw=value.trim();
  if (isIP(raw)===6) raw=`[${raw}]`;
  let url; try { url=new URL(raw.includes('://')?raw:`https://${raw}`); } catch { throw new Error('Enter a valid hostname, IP address, or URL.'); }
  if (!['http:','https:'].includes(url.protocol) || url.username || url.password || url.port) throw new Error('Use HTTP or HTTPS on its standard port, without credentials.');
  const host=url.hostname.replace(/^\[|\]$/g,'').replace(/\.$/,'').toLowerCase();
  if (isIP(host)) { if (!publicIP(host)) throw new Error('Only public internet addresses can be checked.'); }
  else if (host.length>253 || !host.includes('.') || !host.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) || /\.(localhost|local|internal|test|invalid|example|home|lan|onion)$/.test(host)) throw new Error('Enter a public internet hostname.');
  return {host, protocol:url.protocol, port:url.protocol==='https:'?443:80, origin:`${url.protocol}//${isIP(host)===6?`[${host}]`:host}`, pathIgnored:url.pathname!=='/' || !!url.search || !!url.hash};
}
function networkKey(ip) {
  if (isIP(ip)===4) return ip;
  if (isIP(ip)!==6) throw new Error('Invalid source');
  let value=ip.toLowerCase();
  if(value.includes('.')) {const i=value.lastIndexOf(':');const b=value.slice(i+1).split('.').map(Number);value=value.slice(0,i+1)+((b[0]<<8)|b[1]).toString(16)+':'+((b[2]<<8)|b[3]).toString(16);}
  const [a,b]=value.split('::'),left=a?a.split(':'):[],right=b?b.split(':'):[];
  const groups=value.includes('::')?[...left,...Array(8-left.length-right.length).fill('0'),...right]:left;
  const n=groups.map(x=>parseInt(x,16));
  if(n.slice(0,5).every(x=>x===0)&&n[5]===65535)return `${n[6]>>8}.${n[6]&255}.${n[7]>>8}.${n[7]&255}`;
  return n.slice(0,4).map(x=>x.toString(16)).join(':')+'::/64';
}
async function resolveTarget(target, resolver=new Resolver({timeout:1500,tries:1})) {
  if (isIP(target.host)) return {addresses:[target.host],records:{},note:'An IP literal does not require forward DNS.'};
  const timer=setTimeout(()=>resolver.cancel(),2000);
  try {
    const results=await Promise.allSettled([resolver.resolve4(target.host),resolver.resolve6(target.host)]);
    for(const result of results) if(result.status==='rejected' && !['ENODATA','ENOTFOUND'].includes(result.reason.code)) throw new Error('DNS lookup timed out or failed.');
    const addresses=results.flatMap(r=>r.status==='fulfilled'?r.value:[]);
    if(!addresses.length) throw new Error('No public A or AAAA records found.');
    if(addresses.length>32 || addresses.some(ip=>!publicIP(ip))) throw new Error('This hostname resolves to a restricted address and cannot be checked.');
    return {addresses,records:{A:addresses.filter(ip=>isIP(ip)===4),AAAA:addresses.filter(ip=>isIP(ip)===6)}};
  } finally {clearTimeout(timer);resolver.cancel();}
}

module.exports={publicIP,parseTarget,networkKey,resolveTarget};
