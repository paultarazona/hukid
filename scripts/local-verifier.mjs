// Local verifier of the "local" profile (ADR-0037): lab TLS material and a
// loopback HTTPS front that exposes only the wallet's OID4VP paths.
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { createServer } from 'node:https';
import path from 'node:path';

const files = (state) => {
  const dir = path.join(state, 'verifier');
  const f = (name) => path.join(dir, name);
  return { dir, ca: f('lab-ca.pem'), cert: f('server.pem'), key: f('server-key.pem'), issuerKeys: f('issuer-keys.json'), publicKey: f('verifier-public.jwk.json') };
};
export const verifierFiles = files;

export function ensureLabTls(state) {
  const f = files(state);
  mkdirSync(f.dir, { recursive: true, mode: 0o700 });
  if (existsSync(f.ca) && existsSync(f.cert) && existsSync(f.key)) return f;
  const caKey = path.join(f.dir, 'lab-ca-key.pem');
  const csr = path.join(f.dir, 'server.csr');
  const ext = path.join(f.dir, 'server.ext');
  const openssl = (args) => {
    const r = spawnSync('openssl', args, { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`openssl ${args[0]} falló`);
  };
  const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes'];
  try {
    openssl(['req', '-x509', ...ec, '-keyout', caKey, '-out', f.ca, '-days', '30', '-subj', '/CN=HukID Local Lab CA',
      '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign']);
    openssl(['req', ...ec, '-keyout', f.key, '-out', csr, '-subj', '/CN=127.0.0.1']);
    writeFileSync(ext, 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n');
    openssl(['x509', '-req', '-in', csr, '-CA', f.ca, '-CAkey', caKey, '-CAcreateserial', '-out', f.cert, '-days', '30', '-extfile', ext]);
    chmodSync(f.key, 0o600);
  } finally {
    // Without the CA key nothing else can be signed with the lab CA.
    for (const file of [caKey, csr, ext, path.join(f.dir, 'lab-ca.srl')]) rmSync(file, { force: true });
  }
  return f;
}

const allowed = (method, url) =>
  (method === 'GET' && /^\/oid4vp\/request\/[A-Za-z0-9_-]+$/.test(url)) || (method === 'POST' && url === '/oid4vp/response');

export function startVerifierTls(state, port, apiPort) {
  const f = files(state);
  const server = createServer({ cert: readFileSync(f.cert), key: readFileSync(f.key), minVersion: 'TLSv1.2' }, (req, res) => {
    if (!allowed(req.method, req.url)) { res.writeHead(404, { 'Cache-Control': 'no-store' }).end(); return; }
    const upstream = request({ host: '127.0.0.1', port: apiPort, method: req.method, path: req.url, headers: { ...req.headers, host: `127.0.0.1:${apiPort}` }, timeout: 15000 }, (answer) => {
      res.writeHead(answer.statusCode, answer.headers);
      answer.pipe(res);
    });
    upstream.on('timeout', () => upstream.destroy());
    upstream.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.pipe(upstream);
  });
  return new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', () => resolve(server)); });
}
