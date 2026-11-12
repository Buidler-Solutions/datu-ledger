// Renders the dApp in jsdom and pins the behaviour a user actually sees:
// the landing page loads without a wallet present, and the role pages stay
// unreachable until a session exists (the consent flows are guarded).
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { describe, expect, it } from 'vitest';
import App from './App.jsx';

describe('registrar dApp', () => {
  it('renders the landing page without a wallet or node', async () => {
    const container = document.createElement('div');
    document.body.appendChild(container);
    const root = createRoot(container);
    await act(async () => {
      root.render(<App />);
    });
    expect(container.textContent).toContain('DATU · Land Registry');
    // Without the extension the page must say so rather than fail.
    expect(container.textContent).toContain('Signet extension');
    // Role workspaces need a session; they do not render on the landing page.
    expect(container.textContent).not.toContain('Certify the title');
    await act(async () => {
      root.unmount();
    });
  });
});
