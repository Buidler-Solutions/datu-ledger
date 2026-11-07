const json = async (res) => {
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { error: text };
  }
  return { status: res.status, body };
};

export async function nodeGet(nodeUrl, path) {
  const res = await fetch(`${nodeUrl}${path}`);
  return json(res);
}

export async function nodePost(nodeUrl, path, body) {
  const res = await fetch(`${nodeUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return json(res);
}

// The bridge is paired: every call carries the token from Settings.
export function getToken() {
  return localStorage.getItem('datu.bridge.token') || '';
}

export function setToken(token) {
  localStorage.setItem('datu.bridge.token', token.trim());
}

const authHeaders = () => {
  const token = getToken();
  if (!token) throw new Error('paste the bridge pairing token in Services first');
  return { Authorization: `Bearer ${token}` };
};

export async function bridgeGet(bridgeUrl, path) {
  const res = await fetch(`${bridgeUrl}${path}`, { headers: authHeaders() });
  return json(res);
}

export async function bridgePost(bridgeUrl, path, body) {
  const res = await fetch(`${bridgeUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  return json(res);
}

export async function listIdentities(bridgeUrl) {
  const { status, body } = await bridgeGet(bridgeUrl, '/v1/wallet/identities');
  if (status !== 200) throw new Error(body.error || `bridge ${status}`);
  return body.identities || [];
}
