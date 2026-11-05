(() => {
  // Direct Receive visits start closed. An explicit wallet link opens only
  // its matching disclosure; the native controls also work without script.
  if (!document.querySelector("details.receiving-wallet")) return;
  const select = () => {
    const match = location.hash.match(/^#wallet-(.+)$/);
    if (!match) return;
    const wallet = document.getElementById(`wallet-${match[1]}`);
    if (wallet?.matches("details.receiving-wallet")) wallet.open = true;
  };
  window.addEventListener("hashchange", select);
  select();
})();
