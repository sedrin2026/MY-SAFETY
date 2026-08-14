// MY SAFE UI enhancement layer
// 既存の暗号化・IndexedDB・WebAuthn/PRFロジックには触れず、表示だけを補強します。
(function(){
  const $=id=>document.getElementById(id);

  function toggle(inputId,buttonId){
    const input=$(inputId), button=$(buttonId);
    if(!input||!button)return;
    button.addEventListener("click",()=>{
      const visible=input.type==="text";
      input.type=visible?"password":"text";
      button.textContent=visible?"表示する":"隠す";
    });
  }

  toggle("masterPassword","toggleMasterPassword");
  toggle("setupPassword","toggleSetupPassword");
  toggle("setupPassword2","toggleSetupPassword2");

  // 既存app.jsが設定する文言を、今回のPINコードUIに合わせます。
  const status=$("passkeyStatus");
  if(status){
    const observer=new MutationObserver(()=>{
      if(status.textContent.includes("指紋")||status.textContent.includes("顔認証")){
        status.textContent="🔑 端末のPINコードで認証できます。";
      }
    });
    observer.observe(status,{childList:true,subtree:true,characterData:true});
    if(status.textContent.includes("指紋")||status.textContent.includes("顔認証")){
      status.textContent="🔑 端末のPINコードで認証できます。";
    }
  }

  // 既存app.jsの管理ボタン文言もPINコード表記へ統一。
  const manage=$("passkeyManageBtn");
  if(manage){
    const observer=new MutationObserver(()=>{
      if(manage.textContent.includes("パスキー")){
        manage.textContent=manage.textContent.includes("登録済み")
          ?"🔑 PINコード登録済み":"🔑 PINコード設定";
      }
    });
    observer.observe(manage,{childList:true,subtree:true,characterData:true});
    if(manage.textContent.includes("パスキー")){
      manage.textContent=manage.textContent.includes("登録済み")
        ?"🔑 PINコード登録済み":"🔑 PINコード設定";
    }
  }

  // 解除ボタンの表記も統一。
  const unlock=$("passkeyUnlockBtn");
  if(unlock) unlock.textContent="🔑 PINコードで解除";
})();
