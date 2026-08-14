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

async function setupVault(){
  const p=$("setupPassword").value, p2=$("setupPassword2").value;
  $("setupError").textContent="";
  if(p.length<10){$("setupError").textContent="マスターパスワードは10文字以上にしてください。";return;}
  if(p!==p2){$("setupError").textContent="2つのパスワードが一致しません。";return;}
  const encrypted=await encryptVault({entries:[]},p);
  await dbPut(encrypted);
  $("setupPassword").value=$("setupPassword2").value="";
  hide("setupScreen"); show("lockScreen");
  $("lockMessage").textContent="金庫を作成しました。マスターパスワードで解除してください。";
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
    failedAttempts=0; lockoutUntil=0; $("masterPassword").value="";
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
  clearTimeout(idleTimer);
}

function resetIdle(){
  clearTimeout(idleTimer);
  idleTimer=setTimeout(lock,AUTO_LOCK_MS);
}
["click","touchstart","keydown","pointerdown"].forEach(ev=>document.addEventListener(ev,()=>{if(masterKey)resetIdle();},{passive:true}));

function clearForm(){
  ["f_appName","f_loginId","f_password","f_email","f_phone","f_address","f_holder","f_accountName","f_cardNumber","f_expiry","f_cvv","f_memo"].forEach(id=>{if($(id))$(id).value="";});
  if($("f_category"))$("f_category").value="アプリ"; 
  if($("f_password"))$("f_password").type="password"; 
}
function openEditor(entry=null){
  editingId=entry?.id||null; clearForm();
  $("editorTitle").textContent=entry?"編集":"新規登録";
  if($("deleteEntryBtn")) $("deleteEntryBtn").classList.toggle("hidden",!entry);
  if(entry){
    for(const [k,id] of Object.entries({category:"f_category",appName:"f_appName",loginId:"f_loginId",password:"f_password",email:"f_email",phone:"f_phone",address:"f_address",holder:"f_holder",accountName:"f_accountName",cardNumber:"f_cardNumber",expiry:"f_expiry",cvv:"f_cvv"})){
      if($(id)) $(id).value=entry[k]||"";
    }
  }
  hide("vaultScreen"); show("editorScreen");
}
function readForm(){
  return {
    id:editingId||uuid(), 
    category:$("f_category")?$("f_category").value:"アプリ", 
    appName:$("f_appName")?$("f_appName").value.trim():"",
    loginId:$("f_loginId")?$("f_loginId").value:"", 
    password:$("f_password")?$("f_password").value:"", 
    email:$("f_email")?$("f_email").value:"",
    phone:"", address:"", holder:"", accountName:"", cardNumber:"", expiry:"", cvv:""
  };
}
async function saveEntry(){
  const e=readForm();
  if(!e.appName){alert("サービス名・アプリ名を入力してください。");return;}
  const idx=vault.entries.findIndex(x=>x.id===e.id);
  if(idx>=0)vault.entries[idx]=e; else vault.entries.unshift(e);
  await persist(); hide("editorScreen"); show("vaultScreen"); render();
}
async function deleteEntry(){
  if(!editingId)return;
  if(!confirm("この登録を削除しますか？"))return;
  vault.entries=vault.entries.filter(e=>e.id!==editingId);
  await persist(); hide("editorScreen"); show("vaultScreen"); render();
}
async function persist(){
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
  const list=$("entryList");
  if(!list)return;
  const items=currentCategory==="all"?vault.entries:vault.entries.filter(e=>e.category===currentCategory);
  if($("categoryLabel")) $("categoryLabel").textContent=currentCategory==="all"?"すべて":currentCategory;
  list.innerHTML="";
  if(!items.length){list.innerHTML='<div class="muted" style="padding:30px;text-align:center">登録はありません</div>';return;}
  for(const e of items){
    const div=document.createElement("article"); div.className="entry";
    
    const infoDiv=document.createElement("div");
    const title=document.createElement("h3"); title.style.margin="0 0 4px 0"; title.style.fontSize="16px"; title.textContent=e.appName;
    const cat=document.createElement("small"); cat.className="muted"; cat.textContent=`${e.category} ・ ${e.loginId || 'ID未設定'}`;
    infoDiv.append(title,cat);

    const btn=document.createElement("button"); btn.className="small"; btn.textContent="開く";
    btn.onclick=()=>openEditor(e);
    
    div.append(infoDiv,btn); 
    list.appendChild(div);
  }
}

async function init(){
  if("serviceWorker" in navigator) navigator.serviceWorker.register("./sw.js").catch(()=>{});
  const exists=await hasVault();
  if(exists){hide("setupBtn");}
  else {show("setupBtn");}
}

if($("setupBtn")) $("setupBtn").onclick=()=>{hide("lockScreen");show("setupScreen");};
if($("backLockBtn")) $("backLockBtn").onclick=()=>{hide("setupScreen");show("lockScreen");};
if($("createVaultBtn")) $("createVaultBtn").onclick=setupVault;
if($("unlockBtn")) $("unlockBtn").onclick=unlock;
if($("masterPassword")) $("masterPassword").addEventListener("keydown",e=>{if(e.key==="Enter")unlock();});
if($("lockBtn")) $("lockBtn").onclick=lock;
if($("addBtn")) $("addBtn").onclick=()=>openEditor();
if($("closeEditorBtn")) $("closeEditorBtn").onclick=()=>{hide("editorScreen");show("vaultScreen");};
if($("saveEntryBtn")) $("saveEntryBtn").onclick=saveEntry;
if($("deleteEntryBtn")) $("deleteEntryBtn").onclick=deleteEntry;

if($("togglePw")) {
  $("togglePw").onclick=()=>{
    const i=$("masterPassword");
    i.type=i.type==="password"?"text":"password";
    $("togglePw").textContent=i.type==="password"?"表示":"隠す";
  };
}

if($("showPasswordCheck")) {
  $("showPasswordCheck").onchange=(e)=>{
    const i=$("masterPassword");
    i.type=e.target.checked?"text":"password";
  };
}

document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>{
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));b.classList.add("active");
  currentCategory=b.dataset.category;render();
});

init();
