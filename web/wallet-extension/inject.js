(() => {
  const PAGE = 'datu-dapp';
  const WALLET = 'datu-wallet';

  const post = (msg) => window.postMessage({ source: WALLET, ...msg }, '*');

  // Announce ourselves and fetch the wallet state so the dApp knows, right at
  // page load, whether the extension is active, which wallets are paired, and
  // which identities are unlocked in the panel.
  try {
    chrome.runtime.sendMessage({ kind: 'datu-hello' }, (resp) => {
      if (chrome.runtime.lastError) return;
      if (resp && resp.ok) post({ kind: 'state', state: resp.result });
    });
  } catch {}

  window.addEventListener('message', (ev) => {
    const d = ev.data;
    if (!d || d.source !== PAGE || !d.id) return;
    try {
      chrome.runtime.sendMessage(
        { kind: 'datu-rpc', id: d.id, action: d.action, payload: d.payload },
        (resp) => {
          const err = chrome.runtime.lastError;
          if (err) {
            post({ id: d.id, ok: false, error: err.message });
            return;
          }
          if (resp && resp.ok) {
            post({ id: d.id, ok: true, result: resp.result });
          }
        }
      );
    } catch (e) {
      post({ id: d.id, ok: false, error: String(e) });
    }
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.kind === 'datu-rpc-result') {
      post({ id: msg.id, ok: msg.ok, error: msg.error, result: msg.result });
    }
    if (msg && msg.kind === 'datu-state') {
      post({ kind: 'state', state: msg.state });
    }
  });
})();
