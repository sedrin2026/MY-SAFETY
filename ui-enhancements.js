// UI補強レイヤー（既存の暗号化やロジックには触れず、表示の互換性を担保します）
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

  toggle("setupPassword","toggleSetupPassword");
  toggle("setupPassword2","toggleSetupPassword2");
})();
