'use strict';
(()=>{
 const form=document.getElementById('unlock-form'),input=document.getElementById('passcode'),button=document.getElementById('unlock-button'),status=document.getElementById('login-status');
 let encrypted=null,busy=false;
 async function unlock(event){
  event.preventDefault();if(busy||!input.value)return;busy=true;button.disabled=true;status.textContent='正在驗證並解鎖資料…';
  let passcode=input.value;input.value='';
  try{
   if(!crypto.subtle||!window.DecompressionStream)throw new Error('unsupported');
   if(!encrypted){const r=await fetch('catalog.enc',{cache:'no-store'});if(!r.ok)throw new Error('network');encrypted=new Uint8Array(await r.arrayBuffer());}
   const header=new TextDecoder().decode(encrypted.slice(0,8));if(header!=='CUFAMDC1')throw new Error('format');
   const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(passcode),'PBKDF2',false,['deriveKey']);passcode='';
   const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:encrypted.slice(8,24),iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
   const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:encrypted.slice(24,36),additionalData:encrypted.slice(0,8),tagLength:128},key,encrypted.slice(36));
   const stream=new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'));
   const data=await new Response(stream).json();if(!Array.isArray(data.records))throw new Error('format');
   document.getElementById('login').hidden=true;document.getElementById('app').hidden=false;document.getElementById('logout').hidden=false;document.getElementById('directory-link').hidden=false;status.textContent='';
   document.title='崇右表演藝術系｜Model Cards';window.dispatchEvent(new CustomEvent('cufa:unlock',{detail:data.records}));
  }catch(error){
   passcode='';status.textContent=error.message==='unsupported'?'請使用最新版 Chrome、Edge 或 Safari 開啟此網站。':error.message==='network'?'資料讀取失敗，請確認網路後再試。':'通行碼不正確，或加密資料無法解鎖。請重新輸入。';input.focus();
  }finally{busy=false;button.disabled=false;}
 }
 form.addEventListener('submit',unlock);
 document.getElementById('logout').onclick=()=>{
  document.getElementById('gallery').close();document.getElementById('gallery-grid').replaceChildren();window.dispatchEvent(new Event('cufa:lock'));
  document.getElementById('app').replaceChildren();document.getElementById('app').hidden=true;document.getElementById('login').hidden=false;document.getElementById('logout').hidden=true;document.getElementById('directory-link').hidden=true;
  input.value='';status.textContent='已登出。';history.replaceState(null,'',location.pathname);document.title='崇右 Model Cards｜登入';window.scrollTo(0,0);input.focus();
 };
})();
