/*
 MY SAFE v1
 - No server / no fetch / no analytics
 - Vault data stored in IndexedDB only
 - Vault payload encrypted with AES-GCM
 - Master password is never stored
 - Key derived with PBKDF2-SHA-256
*/
const DB_NAME = "my-safe-db";
const DB_VERSION = 1;
const STORE = "vault";
const RECORD_KEY = "main";
const PBKDF2_ITERATIONS = 600000;
const AUTO_LOCK_MS = 5 * 60 * 1000;

let vault = { entries: [] };
let masterKey = null;
let currentCategory = "all";
let editingId = null;
let idleTimer = null;
let failedAttempts = 0;
let lockoutUntil = 0;
const MAX_VIEW_HISTORY = 100;
const PASSKEY_KEY = "passkey";
const PASSKEY_PRF_SALT_BYTES = 32;

const $ = id => document.getElementById(id);

function bufToB64(buf){return btoa(String.fromCharCode(...new Uint8Array(buf)));}
function b64ToBuf(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
function uuid(){return crypto.randomUUID ? crypto.randomUUID() : Date.now()+"-"+Math.random().toString(16).slice(2);}

function openDB(){
  return new Promise((resolve,reject)=>{
    const req=indexedDB.open(DB_NAME,DB_VERSION);
    req.onupgradeneeded=()=>req.result.createObjectStore(STORE);
    req.onsuccess=()=>resolve(req.result);
    req.onerror=()=>reject(req.error);
  });
}
async function dbGet(){
  const db=await openDB();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction(STORE,"readonly"), req=tx.objectStore(STORE).get(RECORD_KEY);
    req.onsuccess=()=>resolve(req.result||null); req.onerror=()=>reject(req.error);
  });
}
async function dbPut(value){
  const db=await openDB();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction(STORE,"readwrite");
    tx.objectStore(STORE).put(value,RECORD_KEY);
    tx.oncomplete=resolve; tx.onerror=()=>reject(tx.error);
  });
}

async function dbGetKey(key){
  const db=await openDB();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction(STORE,"readonly"), req=tx.objectStore(STORE).get(key);
    req.onsuccess=()=>resolve(req.result||null); req.onerror=()=>reject(req.error);
  });
}
async function dbPutKey(key,value){
  const db=await openDB();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction(STORE,"readwrite");
    tx.objectStore(STORE).put(value,key);
    tx.oncomplete=resolve; tx.onerror=()=>reject(tx.error);
  });
}
async function dbDeleteKey(key){
  const db=await openDB();
  return new Promise((resolve,reject)=>{
    const tx=db.transaction(STORE,"readwrite");
    tx.objectStore(STORE).delete(key);
    tx.oncomplete=resolve; tx.onerror=()=>reject(tx.error);
  });
}

async function deriveKey(password,salt){
  const material=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey(
    {name:"PBKDF2",salt,iterations:PBKDF2_ITERATIONS,hash:"SHA-256"},
    material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]
  );
}

async function encryptVault(data,password,existingSalt){
  const salt=existingSalt||crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await deriveKey(password,salt);
  const plain=new TextEncoder().encode(JSON.stringify(data));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,plain);
  return {version:1,salt:bufToB64(salt),iv:bufToB64(iv),ciphertext:bufToB64(cipher)};
}

async function decryptVault(record,password){
  const salt=b64ToBuf(record.salt), iv=b64ToBuf(record.iv), cipher=b64ToBuf(record.ciphertext);
  const key=await deriveKey(password,salt);
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,cipher);
  return {data:JSON.parse(new TextDecoder().decode(plain)),key};
}

function show(id){$(id).classList.remove("hidden")}
function hide(id){$(id).classList.add("hidden")}

async function hasVault(){return !!(await dbGet());}


function passkeySupported(){
  return window.isSecureContext &&
    !!window.PublicKeyCredential &&
    !!navigator.credentials &&
    typeof navigator.credentials.create==="function" &&
    typeof navigator.credentials.get==="function";
}

function randomBytes(n){
  return crypto.getRandomValues(new Uint8Array(n));
}

function arrayBufToB64(buf){
  return bufToB64(buf);
}

function b64ToArrayBuf(s){
  return b64ToBuf(s);
}

async function derivePasskeyWrapKey(prfBytes){
  return crypto.subtle.importKey(
    "raw", prfBytes, {name:"HKDF"}, false, ["deriveKey"]
  ).then(material=>crypto.subtle.deriveKey(
    {name:"HKDF",hash:"SHA-256",salt:new TextEncoder().encode("MY-SAFE-PASSKEY-V1"),info:new TextEncoder().encode("vault-wrap-key")},
    material,
    {name:"AES-GCM",length:256},
    false,
    ["encrypt","decrypt"]
  ));
}

async function wrapMasterPasswordWithPrf(password,prfBytes){
  const key=await derivePasskeyWrapKey(prfBytes);
  const iv=randomBytes(12);
  const plain=new TextEncoder().encode(password);
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,plain);
  return {iv:arrayBufToB64(iv),ciphertext:arrayBufToB64(cipher)};
}

async function unwrapMasterPasswordWithPrf(record,prfBytes){
  const key=await derivePasskeyWrapKey(prfBytes);
  const plain=await crypto.subtle.decrypt(
    {name:"AES-GCM",iv:b64ToArrayBuf(record.iv)},
    key,
    b64ToArrayBuf(record.ciphertext)
  );
  return new TextDecoder().decode(plain);
}

function bytesToBase64Url(bytes){
  const b=bytes instanceof ArrayBuffer?new Uint8Array(bytes):bytes;
  let s="";
  for(const x of b)s+=String.fromCharCode(x);
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

async function registerPasskey(){
  if(!passkeySupported()){
    throw new Error("このブラウザまたは端末では、現在のパスキー方式（WebAuthn PRF）が利用できません。");
  }
  if(!masterKey){
    throw new Error("先にマスターパスワードで金庫を解除してください。");
  }

  const existing=await dbGetKey(PASSKEY_KEY);
  if(existing) throw new Error("パスキーはすでに登録されています。");

  const password=window.prompt("パスキー登録の確認です。現在のマスターパスワードを入力してください。");
  if(password===null) return;
  const record=await dbGet();
  try{ await decryptVault(record,password); }
  catch(e){ throw new Error("マスターパスワードが違います。"); }

  const salt=randomBytes(PASSKEY_PRF_SALT_BYTES);
  const challenge=randomBytes(32);
  const userId=randomBytes(32);

  const credential=await navigator.credentials.create({
    publicKey:{
      challenge,
      rp:{name:"MY SAFE",id:location.hostname},
      user:{id:userId,name:"my-safe-user",displayName:"MY SAFE"},
      pubKeyCredParams:[
        {type:"public-key",alg:-7},
        {type:"public-key",alg:-257}
      ],
      authenticatorSelection:{
        residentKey:"required",
        requireResidentKey:true,
        userVerification:"required"
      },
      timeout:60000,
      attestation:"none",
      extensions:{
        prf:{eval:{first:salt}}
      }
    }
  });

  const ext=credential.getClientExtensionResults?.()||{};
  const prf=ext.prf?.results?.first;
  if(!prf) throw new Error("この端末のパスキーはPRF機能に対応していないため、MY SAFEのローカル金庫解除には使用できません。");

  const wrapped=await wrapMasterPasswordWithPrf(password,prf);
  await dbPutKey(PASSKEY_KEY,{
    version:1,
    credentialId:bytesToBase64Url(credential.rawId),
    salt:arrayBufToB64(salt),
    iv:wrapped.iv,
    ciphertext:wrapped.ciphertext,
    createdAt:new Date().toISOString()
  });
  updatePasskeyUI();
}

async function unlockWithPasskey(){
  const cfg=await dbGetKey(PASSKEY_KEY);
  if(!cfg) throw new Error("パスキーが登録されていません。");

  if(!passkeySupported()){
    throw new Error("このブラウザまたは端末ではパスキー解除を利用できません。");
  }

  const challenge=randomBytes(32);
  const credential=await navigator.credentials.get({
    publicKey:{
      challenge,
      rpId:location.hostname,
      allowCredentials:[{
        type:"public-key",
        id:b64ToArrayBuf(cfg.credentialId)
      }],
      userVerification:"required",
      timeout:60000,
      extensions:{
        prf:{eval:{first:b64ToArrayBuf(cfg.salt)}}
      }
    }
  });

  const ext=credential.getClientExtensionResults?.()||{};
  const prf=ext.prf?.results?.first;
  if(!prf) throw new Error("パスキーから安全な解除キーを取得できませんでした。");

  const password=await unwrapMasterPasswordWithPrf(cfg,prf);
  const record=await dbGet();
  const result=await decryptVault(record,password);

  vault=result.data;
  masterKey=result.key;
  failedAttempts=0;
  lockoutUntil=0;
  ensureViewHistory();
  await recordView();
  hide("lockScreen");
  show("vaultScreen");
  render();
  resetIdle();
}

async function updatePasskeyUI(){
  const cfg=await dbGetKey(PASSKEY_KEY);
  const btn=$("passkeyUnlockBtn");
  const manage=$("passkeyManageBtn");
  const status=$("passkeyStatus");
  if(btn) btn.classList.toggle("hidden",!cfg);
  if(status){
    if(cfg) status.textContent="🔑 パスキー登録済み";
    else status.textContent=passkeySupported()
      ?"パスキーを登録すると、指紋・顔認証などで解除できます。"
      :"このブラウザではパスキー解除を利用できません。";
  }
  if(manage) manage.textContent=cfg?"🔑 パスキー登録済み":"🔑 パスキー登録";
}

async function setupVault(){
  const p=$("setupPassword").value, p2=$("setupPassword2").value;
  $("setupError").textContent="";
  if(p.length<10){$("setupError").textContent="マスターパスワードは10文字以上にしてください。";return;}
  if(p!==p2){$("setupError").textContent="2つのパスワードが一致しません。";return;}
  const encrypted=await encryptVault({entries:[],viewHistory:[]},p);
  await dbPut(encrypted);
  $("setupPassword").value=$("setupPassword2").value="";
  hide("setupScreen"); show("lockScreen");
  $("lockMessage").textContent="金庫を作成しました。マスターパスワードで解除してください。";
}


function ensureViewHistory(){
  if(!Array.isArray(vault.viewHistory)) vault.viewHistory=[];
}

function formatViewDate(iso){
  const d=new Date(iso);
  if(Number.isNaN(d.getTime())) return "日時不明";
  return new Intl.DateTimeFormat("ja-JP",{
    year:"numeric",month:"2-digit",day:"2-digit",
    hour:"2-digit",minute:"2-digit",second:"2-digit"
  }).format(d);
}

function updateViewHistoryUI(){
  ensureViewHistory();
  const now=new Date();
  const today=vault.viewHistory.filter(item=>{
    const t=new Date(item.at);
    return !Number.isNaN(t.getTime()) &&
      t.getFullYear()===now.getFullYear() &&
      t.getMonth()===now.getMonth() &&
      t.getDate()===now.getDate();
  });
  $("todayViewCount").textContent=`${today.length}回`;
  $("lastViewedAt").textContent=vault.viewHistory[0]
    ? `最終閲覧：${formatViewDate(vault.viewHistory[0].at)}`
    : "最終閲覧：—";
}

function renderViewHistoryList(){
  ensureViewHistory();
  const box=$("historyItems");
  box.innerHTML="";
  if(!vault.viewHistory.length){
    box.innerHTML='<div class="muted history-empty">閲覧履歴はありません</div>';
    return;
  }
  for(const item of vault.viewHistory){
    const row=document.createElement("div");
    row.className="history-row";
    row.textContent=`🔓 ${formatViewDate(item.at)}`;
    box.appendChild(row);
  }
}

async function recordView(){
  ensureViewHistory();
  vault.viewHistory.unshift({at:new Date().toISOString()});
  if(vault.viewHistory.length>MAX_VIEW_HISTORY) vault.viewHistory.length=MAX_VIEW_HISTORY;
  await persist();
  updateViewHistoryUI();
}

async function unlock(){
  const now=Date.now();
  if(now<lockoutUntil){$("lockError").textContent=`しばらく待ってください（あと${Math.ceil((lockoutUntil-now)/1000)}秒）。`;return;}
  const p=$("masterPassword").value;
  if(!p){$("lockError").textContent="マスターパスワードを入力してください。";return;}
  $("lockError").textContent="確認中…";
  try{
    const record=await dbGet();
    const result=await decryptVault(record,p);
    vault=result.data; masterKey=result.key;
    ensureViewHistory();
    failedAttempts=0; lockoutUntil=0; $("masterPassword").value="";
    await recordView();
    hide("lockScreen"); show("vaultScreen"); render(); resetIdle();
  }catch(e){
    failedAttempts++;
    const delay=Math.min(30000,1000*Math.pow(2,Math.max(0,failedAttempts-3)));
    if(failedAttempts>=3) lockoutUntil=Date.now()+delay;
    $("lockError").textContent="パスワードが違います。";
    $("masterPassword").value="";
  }
}

function lock(){
  vault={entries:[]}; masterKey=null; editingId=null;
  hide("editorScreen"); hide("vaultScreen"); show("lockScreen");
  $("lockError").textContent=""; $("masterPassword").value="";
  $("viewHistoryList").classList.add("hidden");
  clearTimeout(idleTimer);
}

function resetIdle(){
  clearTimeout(idleTimer);
  idleTimer=setTimeout(lock,AUTO_LOCK_MS);
}
["click","touchstart","keydown","pointerdown"].forEach(ev=>document.addEventListener(ev,()=>{if(masterKey)resetIdle();},{passive:true}));

function clearForm(){
  ["f_appName","f_loginId","f_password","f_email","f_phone","f_address","f_holder","f_accountName","f_cardNumber","f_expiry","f_cvv"].forEach(id=>$(id).value="");
  $("f_category").value="アプリ"; $("f_password").type="password"; $("togglePw").textContent="表示";
}
function openEditor(entry=null){
  editingId=entry?.id||null; clearForm();
  $("editorTitle").textContent=entry?"編集":"新規登録";
  $("deleteEntryBtn").classList.toggle("hidden",!entry);
  if(entry){
    for(const [k,id] of Object.entries({category:"f_category",appName:"f_appName",loginId:"f_loginId",password:"f_password",email:"f_email",phone:"f_phone",address:"f_address",holder:"f_holder",accountName:"f_accountName",cardNumber:"f_cardNumber",expiry:"f_expiry",cvv:"f_cvv"})) $(id).value=entry[k]||"";
  }
  show("editorScreen");
}
function readForm(){
  return {
    id:editingId||uuid(), category:$("f_category").value, appName:$("f_appName").value.trim(),
    loginId:$("f_loginId").value, password:$("f_password").value, email:$("f_email").value,
    phone:$("f_phone").value, address:$("f_address").value, holder:$("f_holder").value,
    accountName:$("f_accountName").value, cardNumber:$("f_cardNumber").value,
    expiry:$("f_expiry").value, cvv:$("f_cvv").value
  };
}
async function saveEntry(){
  const e=readForm();
  if(!e.appName){alert("サービス名・アプリ名を入力してください。");return;}
  const idx=vault.entries.findIndex(x=>x.id===e.id);
  if(idx>=0)vault.entries[idx]=e; else vault.entries.unshift(e);
  await persist(); hide("editorScreen"); render();
}
async function deleteEntry(){
  if(!editingId)return;
  if(!confirm("この登録を削除しますか？"))return;
  vault.entries=vault.entries.filter(e=>e.id!==editingId);
  await persist(); hide("editorScreen"); render();
}
async function persist(){
  // The master password is never kept in an input after unlock.
  // Re-encrypt using the CryptoKey held only in memory for this session.
  await persistWithLiveKey();
}
async function persistWithLiveKey(){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const plain=new TextEncoder().encode(JSON.stringify(vault));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},masterKey,plain);
  const old=await dbGet();
  await dbPut({version:1,salt:old.salt,iv:bufToB64(iv),ciphertext:bufToB64(cipher)});
}

function render(){
  updateViewHistoryUI();
  const list=$("entryList");
  const items=currentCategory==="all"?vault.entries:vault.entries.filter(e=>e.category===currentCategory);
  $("categoryLabel").textContent=currentCategory==="all"?"すべて":currentCategory;
  list.innerHTML="";
  if(!items.length){list.innerHTML='<div class="muted" style="padding:30px;text-align:center">登録はありません</div>';return;}
  for(const e of items){
    const div=document.createElement("article"); div.className="entry";
    const title=document.createElement("h3"); title.textContent=e.appName;
    const cat=document.createElement("small"); cat.textContent=e.category;
    const btn=document.createElement("button"); btn.className="small"; btn.textContent="開く";
    btn.onclick=()=>openEditor(e);
    div.append(title,cat,document.createElement("br"),btn); list.appendChild(div);
  }
}

$("viewHistoryBtn").onclick=()=>{
  renderViewHistoryList();
  show("viewHistoryList");
};
$("closeHistoryBtn").onclick=()=>hide("viewHistoryList");


$("passkeyUnlockBtn").onclick=async()=>{
  $("lockError").textContent="パスキーを確認中…";
  try{
    await unlockWithPasskey();
    $("lockError").textContent="";
  }catch(e){
    $("lockError").textContent=e?.message||"パスキー解除に失敗しました。";
  }
};

$("passkeyManageBtn").onclick=async()=>{
  try{
    if(!masterKey){
      alert("先にマスターパスワードで金庫を解除してください。");
      return;
    }
    const existing=await dbGetKey(PASSKEY_KEY);
    if(existing){
      const remove=confirm("登録済みのパスキーを削除しますか？\n\n削除してもマスターパスワードはそのまま使えます。");
      if(remove){
        await dbDeleteKey(PASSKEY_KEY);
        updatePasskeyUI();
        alert("パスキー登録を削除しました。");
      }
      return;
    }
    await registerPasskey();
    alert("パスキーを登録しました。次回からパスキーで解除できます。");
  }catch(e){
    alert(e?.message||"パスキー登録に失敗しました。");
  }
};

async function init(){
  if("serviceWorker" in navigator) navigator.serviceWorker.register("./sw.js").catch(()=>{});
  await updatePasskeyUI();
  const exists=await hasVault();
  if(exists){hide("setupBtn");$("lockMessage").textContent="マスターパスワードでロック解除してください。";}
  else {show("setupBtn");$("lockMessage").textContent="まだ金庫がありません。初回設定から作成してください。";}
}

$("setupBtn").onclick=()=>{hide("lockScreen");show("setupScreen");};
$("backLockBtn").onclick=()=>{hide("setupScreen");show("lockScreen");};
$("createVaultBtn").onclick=setupVault;
$("unlockBtn").onclick=unlock;
$("masterPassword").addEventListener("keydown",e=>{if(e.key==="Enter")unlock();});
$("lockBtn").onclick=lock;
$("addBtn").onclick=()=>openEditor();
$("closeEditorBtn").onclick=()=>hide("editorScreen");
$("saveEntryBtn").onclick=saveEntry;
$("deleteEntryBtn").onclick=deleteEntry;
$("togglePw").onclick=()=>{const i=$("f_password");i.type=i.type==="password"?"text":"password";$("togglePw").textContent=i.type==="password"?"表示":"隠す";};
document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>{
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));b.classList.add("active");
  currentCategory=b.dataset.category;render();
});

init();
