(() => {
  const PAGE = 'datu-dapp';
  const WALLET = 'datu-wallet';

  const post = (msg) => window.postMessage({ source: WALLET, ...msg }, '*');

  // After an extension reload, every already-open tab keeps this orphaned
  // content script - chrome.runtime is dead here. Answer with a clear error
  // instead of a silent timeout, so the dApp can tell the user to refresh.
  const contextAlive = () => {
    try {
      return Boolean(chrome.runtime && chrome.runtime.id);
    } catch {
      return false;
    }
  };
  const DEAD = 'the Signet extension was reloaded - refresh this page to reconnect';

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

  if (contextAlive()) {
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg && msg.kind === 'datu-rpc-result') {
        post({ id: msg.id, ok: msg.ok, error: msg.error, result: msg.result });
      }
      if (msg && msg.kind === 'datu-state') {
        post({ kind: 'state', state: msg.state });
      }
    });
  } else {
    // Orphaned after a reload: keep answering pings so the dApp shows the
    // refresh hint instead of an unexplained timeout.
    window.addEventListener('message', (ev) => {
      const d = ev.data;
      if (!d || d.source !== PAGE || !d.id || d.action !== 'ping') return;
      post({ id: d.id, ok: false, error: DEAD });
    });
  }
})();
