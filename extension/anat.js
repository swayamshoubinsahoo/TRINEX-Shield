const BR=['paypal','google','apple','amazon','microsoft','sbi','hdfcbank','paytm','netflix','facebook','irctc'],BT=['xyz','top','tk','ml','ga','click','zip','icu','cfd'];
function analyse(url){if(!/^https?:/i.test(url))return null;const m=url.match(/^(https?:\/\/)?([^\/?#]*)([\/?#].*)?$/i);if(!m)return null;
const sc=m[1]||'',host=m[2],rest=m[3]||'',L=host.split('.'),tld=L.length>1?L.pop():'',dom=L.pop()||'',sub=L.join('.'),fl=[];
if(/xn--/.test(host))fl.push('Punycode: may hide look-alike characters');
if(/[a-z][01]|[01][a-z]/i.test(dom)&&BR.some(b=>dom.replace(/1/g,'l').replace(/0/g,'o')==b))fl.push('Digits swapped for letters in a brand name');
if(BT.includes(tld))fl.push('Low-reputation TLD .'+tld);
BR.forEach(b=>{if(sub.includes(b))fl.push('Brand "'+b+'" in subdomain, not the real domain')});
if(sc=='http://')fl.push('No HTTPS');
if(/[?&]url=|otp|verify|login/i.test(rest))fl.push('Credential or redirect keywords in the path');
return{sc,sub,dom,tld,rest,fl,host}}
