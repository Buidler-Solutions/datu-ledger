// Tiny static file server: `npm start` then open http://localhost:5174.
// The Signet extension's content script runs on localhost origins, so the
// demo page can reach the wallet without any build step.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';

const ROOT = new URL('.', import.meta.url).pathname;
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

http
  .createServer(async (req, res) => {
    try {
      const path = req.url.split('?')[0] === '/' ? '/index.html' : req.url.split('?')[0];
      const body = await readFile(join(ROOT, path.replace(/^\//, '')));
      res.writeHead(200, { 'Content-Type': TYPES[extname(path)] || 'application/octet-stream' });
      res.end(body);
    } catch {
      res.writeHead(404).end('not found');
    }
  })
  .listen(5174, '127.0.0.1', () => console.log('hello-DATU on http://localhost:5174'));
