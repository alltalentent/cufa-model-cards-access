'use strict';
(()=>{
 const form=document.getElementById('unlock-form'),input=document.getElementById('passcode'),button=document.getElementById('unlock-button'),status=document.getElementById('login-status');
 let busy=false,key=null;
 const packs=new Map();
 async function bytes(name){
  const r=await fetch(name,{signal:AbortSignal.timeout(45000)});
  if(!r.ok)throw new Error('network');
  return new Uint8Array(await r.arrayBuffer());
 }
 async function decode(name,b,k){
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12),additionalData:new TextEncoder().encode(name)},k,b.slice(12));
  const data=await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).json();
  if(!Array.isArray(data))throw new Error('format');
  return data;
 }
 window.loadCardPack=function(name){
  if(!key||!/^fast-v1-[0-8]\.enc$/.test(name))return Promise.reject(new Error('format'));
  if(!packs.has(name)){
   const k=key;
   const pending=bytes(name).then(b=>decode(name,b,k)).catch(e=>{if(packs.get(name)===pending)packs.delete(name);throw e;});
   packs.set(name,pending);
  }
  return packs.get(name);
 };
 async function unlock(event){
  event.preventDefault();if(busy||!input.value)return;busy=true;button.disabled=true;status.textContent='正在驗證並解鎖名單…';
  let passcode=input.value;input.value='';
  try{
   if(!crypto.subtle||!window.DecompressionStream)throw new Error('unsupported');
   const name='fast-v1-index.enc',b=await bytes(name);
   const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(passcode),'PBKDF2',false,['deriveKey']);passcode='';
   const k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:b.slice(0,16),iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
   const records=await decode(name,b.slice(16),k);
   key=k;
   document.getElementById('login').hidden=true;document.getElementById('app').hidden=false;document.getElementById('logout').hidden=false;document.getElementById('directory-link').hidden=false;status.textContent='';
   document.title='崇右表演藝術系｜Model Cards';window.dispatchEvent(new CustomEvent('cufa:unlock',{detail:records}));
  }catch(error){
   passcode='';status.textContent=error.message==='unsupported'?'請使用最新版 Chrome、Edge 或 Safari 開啟此網站。':(error.message==='network'||error.name==='TimeoutError'||error instanceof TypeError)?'資料讀取失敗，請確認網路後再試。':'通行碼不正確，或加密資料無法解鎖。請重新輸入。';input.focus();
  }finally{busy=false;button.disabled=false;}
 }
 form.addEventListener('submit',unlock);
 document.getElementById('logout').onclick=()=>{
  key=null;packs.clear();
  document.getElementById('gallery').close();document.getElementById('gallery-grid').replaceChildren();window.dispatchEvent(new Event('cufa:lock'));
  document.getElementById('app').replaceChildren();document.getElementById('app').hidden=true;document.getElementById('login').hidden=false;document.getElementById('logout').hidden=true;document.getElementById('directory-link').hidden=true;
  input.value='';status.textContent='已登出。';history.replaceState(null,'',location.pathname);document.title='崇右 Model Cards｜登入';window.scrollTo(0,0);input.focus();
 };
})();
