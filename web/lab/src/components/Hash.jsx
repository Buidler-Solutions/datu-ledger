import { useState } from 'react';
import { short } from '../lib/api';

// Monospace hash with one-click copy. Shows the short form, copies the full
// value, and confirms with a tick that fades.
export default function Hash({ value, label, full = false }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="dim">none</span>;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard may be unavailable over http */
    }
  };

  return (
    <button type="button" className="hash" onClick={copy} title={value} aria-label={label || 'copy hash'}>
      <span>{full ? value : short(value)}</span>
      <span className="dim" style={{ fontSize: '0.9em' }}>{copied ? 'copied' : 'copy'}</span>
    </button>
  );
}
