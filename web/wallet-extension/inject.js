(() => {
  const PAGE = 'datu-dapp';
  const WALLET = 'datu-wallet';
  window.addEventListener('message', (ev) => {
    const d = ev.data;
    if (!d || d.source !== PAGE || !d.id) return;
    try {
      chrome.runtime.sendMessage(
        { kind: 'datu-rpc', id: d.id, action: d.action, payload: d.payload },
        (resp) => {
          const err = chrome.runtime.lastError;
          if (err) {
            window.postMessage({ source: WALLET, id: d.id, ok: false, error: err.message }, '*');
            return;
          }
          if (resp && resp.ok) {
            window.postMessage({ source: WALLET, id: d.id, ok: true, result: resp.result }, '*');
          }
        }
      );
    } catch (e) {
      window.postMessage({ source: WALLET, id: d.id, ok: false, error: String(e) }, '*');
    }
  });
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.kind === 'datu-rpc-result') {
      window.postMessage(
        { source: WALLET, id: msg.id, ok: msg.ok, error: msg.error, result: msg.result },
        '*'
      );
    }
  });
})();
