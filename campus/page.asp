<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Cache-Control" content="no-store">
<title>校园网自动登录</title>
<link rel="stylesheet" href="/index_style.css"><link rel="stylesheet" href="/form_style.css">
<script src="/state.js"></script><script src="/general.js"></script><script src="/popup.js"></script>
<style>
.campus-box{padding:15px 20px 24px;color:#fff}.campus-box h2{margin-bottom:8px}.campus-box p{line-height:1.6;color:#d2dce0}.campus-box label{display:block;margin:16px 0 6px}.campus-box input[type=text],.campus-box input[type=password],.campus-box input[type=number]{box-sizing:border-box;width:100%;max-width:360px;padding:9px;border:1px solid #88999f;border-radius:4px;background:#fff;color:#111}.campus-box button{margin:18px 10px 0 0;padding:9px 20px;cursor:pointer}.campus-status{padding:12px;border:1px solid #81949a;border-radius:5px;margin:15px 0;white-space:pre-wrap}.campus-box .campus-error{color:#ffd0c9}.campus-help{font-size:13px}#secure-link{color:#fff;text-decoration:underline;font-weight:bold}
</style>
<script>
// CAMPUS_LOGIN_ADDON_ID -- no private values are embedded in this page.
var custom_settings = <% get_custom_settings(); %>;
var campusPublicKey = '__CAMPUS_PUBLIC_KEY__';
// SHA-256 and RSA-OAEP fallback for HTTP pages, where SubtleCrypto is unavailable.
// Random padding still comes from the browser's crypto.getRandomValues.
function campusHash(data){
  var k=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];
  var h=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225], a=Array.from(data), bits=a.length*8;
  a.push(128); while(a.length%64!==56)a.push(0); for(var i=7;i>=0;i--)a.push(i>=4?0:Math.floor(bits/Math.pow(256,i))%256);
  function rr(x,n){return (x>>>n)|(x<<(32-n));}
  for(var o=0;o<a.length;o+=64){
    var w=new Uint32Array(64);for(i=0;i<16;i++)w[i]=((a[o+4*i]<<24)|(a[o+4*i+1]<<16)|(a[o+4*i+2]<<8)|a[o+4*i+3])>>>0;
    for(i=16;i<64;i++){var x=w[i-15],y=w[i-2];w[i]=(w[i-16]+(rr(x,7)^rr(x,18)^(x>>>3))+w[i-7]+(rr(y,17)^rr(y,19)^(y>>>10)))>>>0;}
    var v=h.slice();for(i=0;i<64;i++){var t1=(v[7]+(rr(v[4],6)^rr(v[4],11)^rr(v[4],25))+((v[4]&v[5])^(~v[4]&v[6]))+k[i]+w[i])>>>0;var t2=((rr(v[0],2)^rr(v[0],13)^rr(v[0],22))+((v[0]&v[1])^(v[0]&v[2])^(v[1]&v[2])))>>>0;v=[(t1+t2)>>>0,v[0],v[1],v[2],(v[3]+t1)>>>0,v[4],v[5],v[6]];}for(i=0;i<8;i++)h[i]=(h[i]+v[i])>>>0;
  }
  var out=new Uint8Array(32);for(i=0;i<32;i++)out[i]=h[i>>2]>>>(24-8*(i%4));return out;
}
function campusMask(seed,n){var out=new Uint8Array(n),p=0,c=0;while(p<n){var b=new Uint8Array(seed.length+4);b.set(seed);b[b.length-4]=c>>>24;b[b.length-3]=c>>>16;b[b.length-2]=c>>>8;b[b.length-1]=c++;var h=campusHash(b);for(var i=0;i<h.length&&p<n;i++)out[p++]=h[i];}return out;}
function campusEncrypt(encoded){
  if(!window.crypto || !window.crypto.getRandomValues || typeof BigInt==='undefined')throw Error('browser crypto unavailable');
  var der=Uint8Array.from(atob(campusPublicKey),function(c){return c.charCodeAt(0)}),pos=0;
  function read(tag){if(der[pos++]!==tag)throw Error('bad public key');var n=der[pos++];if(n&128){var count=n&127;n=0;while(count--)n=n*256+der[pos++];}var start=pos;pos+=n;if(pos>der.length)throw Error('bad public key');return der.slice(start,pos);}
  der=read(48);pos=0;read(48);der=read(3).slice(1);pos=0;der=read(48);pos=0;var mod=read(2),exp=read(2);if(mod[0]===0)mod=mod.slice(1);
  var size=mod.length;if(encoded.length>size-66)throw Error('credentials too long');
  var db=new Uint8Array(size-33);db.set(campusHash(new Uint8Array(0)));db[db.length-encoded.length-1]=1;db.set(encoded,db.length-encoded.length);
  var seed=new Uint8Array(32);window.crypto.getRandomValues(seed);var mask=campusMask(seed,db.length);for(var i=0;i<db.length;i++)db[i]^=mask[i];mask=campusMask(db,32);for(i=0;i<32;i++)seed[i]^=mask[i];
  var em=new Uint8Array(size);em.set(seed,1);em.set(db,33);
  function num(a){var v=BigInt(0);for(var j=0;j<a.length;j++)v=(v<<BigInt(8))+BigInt(a[j]);return v;}
  var n=num(mod),e=num(exp),base=num(em),result=BigInt(1);while(e>0){if(e&BigInt(1))result=result*base%n;base=base*base%n;e=e>>BigInt(1);}
  var out=new Uint8Array(size);for(i=size-1;i>=0;i--){out[i]=Number(result&BigInt(255));result=result>>BigInt(8);}return out;
}
function campusInit(){
  if(typeof show_menu==='function') show_menu();
  document.getElementById('enabled').checked=custom_settings.campuslogin_enabled==='1';
  document.getElementById('interval').value=custom_settings.campuslogin_interval || '15';
  var current=location.pathname.substring(1);
  document.getElementById('current_page').value=current;
  document.getElementById('next_page').value=current;
  campusRefresh();
  setInterval(campusRefresh,5000);
}
async function campusRefresh(){
  try{
    var response=await fetch('/user/campus-login-status.json?cache='+Date.now(),{credentials:'same-origin',cache:'no-store'});
    if(!response.ok) return;
    var s=await response.json();
    var names={disabled:'已关闭',waiting:'等待检查',checking:'正在检查',online:'已在线',uncertain:'登录已提交，状态未确认',error:'检查或登录失败'};
    document.getElementById('status').textContent='状态：'+(names[s.state]||'等待设置')+'\n账号：'+(s.credentials_saved?'已保存':'尚未保存')+(s.checked_at?'\n最近检查：'+s.checked_at:'')+(s.message?'\n'+s.message:'');
  }catch(e){}
}
async function campusSave(){
  var error=document.getElementById('error');error.textContent='';
  if(!window.crypto || !window.crypto.getRandomValues){error.textContent='浏览器不支持安全随机数，请使用较新的浏览器。';return;}
  var enabled=document.getElementById('enabled').checked;
  var interval=Number(document.getElementById('interval').value);
  var username=document.getElementById('username').value;
  var password=document.getElementById('password').value;
  if(!Number.isInteger(interval)||interval<1||interval>1440){error.textContent='间隔请输入 1 到 1440 分钟的整数。';return;}
  if((username&&!password)||(!username&&password)){error.textContent='更新账号时，请同时填写用户名和密码。';return;}
  try{
    var settings=Object.assign({},custom_settings);
    settings.campuslogin_enabled=enabled?'1':'0';
    settings.campuslogin_interval=String(interval);
    if(username&&password){
      var encoded=new TextEncoder().encode(JSON.stringify({username:username,password:password}));
      if(encoded.length>190){error.textContent='用户名和密码合计过长，请缩短后重试。';return;}
      var encrypted=campusEncrypt(encoded);
      settings.campuslogin_secret=btoa(String.fromCharCode.apply(null,encrypted));
    }
    document.getElementById('amng_custom').value=JSON.stringify(settings);
    custom_settings=settings;
    document.getElementById('username').value='';document.getElementById('password').value='';
    document.getElementById('campus-form').submit();
    document.getElementById('status').textContent='正在保存并应用设置，请稍候……';
    setTimeout(campusRefresh,2500);
  }catch(e){error.textContent='无法加密或提交设置，请刷新页面重试。';}
}
</script></head>
<body class="bg" onload="campusInit()"><div id="TopBanner"></div><div id="Loading" class="popup_bg"></div>
<table class="content" align="center" cellpadding="0" cellspacing="0"><tr><td width="17">&nbsp;</td>
<td valign="top" width="202"><div id="mainMenu"></div><div id="subMenu"></div></td>
<td valign="top"><div id="tabMenu" class="submenuBlock"></div>
<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0"><tr><td valign="top">
<table width="760" border="0" cellpadding="4" cellspacing="0" class="FormTitle" id="FormTitle"><tr bgcolor="#4D595D"><td valign="top">
<div class="campus-box"><h2>校园网自动登录</h2>
<p>路由器通过 WAN 检查校园网在线状态；未在线时使用已保存的账号登录。默认关闭。</p>
<div id="status" class="campus-status">正在读取状态……</div>
<p id="error" class="campus-error"></p>
<form id="campus-form" method="post" action="/start_apply.htm" target="campus-frame">
<input type="hidden" name="current_page" id="current_page" value="">
<input type="hidden" name="next_page" id="next_page" value="">
<input type="hidden" name="group_id" value=""><input type="hidden" name="modified" value="0">
<input type="hidden" name="action_mode" value="apply"><input type="hidden" name="action_wait" value="2">
<input type="hidden" name="action_script" value="restart_campuslogin">
<input type="hidden" name="amng_custom" id="amng_custom" value="">
<label><input id="enabled" type="checkbox"> 开启自动检查与登录</label>
<label for="interval">检查间隔（分钟，1–1440）</label><input id="interval" type="number" min="1" max="1440" value="15">
<label for="username">用户名</label><input id="username" type="text" autocomplete="off" maxlength="128">
<label for="password">密码</label><input id="password" type="password" autocomplete="new-password" maxlength="128">
<p class="campus-help">首次启用需要填写用户名和密码；以后仅修改开关或间隔时留空即可保留原账号。密码不会显示在此页面。</p>
<button type="button" id="save" onclick="campusSave()">保存并应用</button>
<button type="button" onclick="campusRefresh()">刷新状态</button>
</form><iframe name="campus-frame" hidden></iframe></div></td></tr></table></td></tr></table>
</td><td width="10">&nbsp;</td></tr></table><div id="footer"></div>
</body></html>
