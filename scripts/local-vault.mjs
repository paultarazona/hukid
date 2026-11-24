// Persistent single-machine Vault Transit profile for local Issuer development.
// State and unseal credentials remain under the ignored .cache directory.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, openSync, closeSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const state = path.resolve(root, process.env.HUKID_LOCAL_STATE_DIR || '.cache/local-issuer');
const cacheRoot = path.resolve(root, '.cache');
const relative = path.relative(cacheRoot, state);
if (relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('HUKID_LOCAL_STATE_DIR debe estar dentro de .cache');
const vaultHome = path.join(state, 'vault');
const configPath = path.join(vaultHome, 'vault.hcl');
const secretsPath = path.join(state, 'vault-secrets.json');
const runtimePath = path.join(state, 'vault-runtime.json');
const pidPath = path.join(state, 'vault.pid');
const vaultBin = process.env.HUKID_VAULT_BIN || path.join(root, '.cache/toolchains/vault-1.18.0/vault.exe');
const port = Number(process.env.HUKID_VAULT_PORT || 18200);
const address = `http://127.0.0.1:${port}`;
const mount = 'transit';
const kekName = 'hukid-claims-kek';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const readJSON = file => JSON.parse(readFileSync(file, 'utf8'));

function run(args, input) {
  const result = spawnSync(vaultBin, args, { cwd: root, encoding: 'utf8', input, windowsHide: true, timeout: 30000, env: { ...process.env, VAULT_ADDR: address } });
  if (result.error || result.status !== 0) throw new Error(`Fallo Vault ${args[0]}: ${(result.stderr || '').trim().split('\n').slice(-2).join('\n')}`);
  return result.stdout;
}

async function api(token, method, route, body) {
  const response = await fetch(`${address}/v1/${route}`, {
    method,
    headers: { 'X-Vault-Token': token, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(5000),
  });
  const text = await response.text();
  let data = {};
  if (text) { try { data = JSON.parse(text); } catch { throw new Error(`Respuesta Vault no JSON (${response.status})`); } }
  if (!response.ok) throw new Error(`Vault ${method} ${route} respondió ${response.status}`);
  return data;
}

async function status() {
  try {
    const response = await fetch(`${address}/v1/sys/seal-status`, { signal: AbortSignal.timeout(1000) });
    if (response.status === 501) return { initialized: false, sealed: true };
    if (!response.ok) return null;
    return await response.json();
  } catch { return null; }
}

async function waitForServer() {
  for (let i = 0; i < 100; i++) {
    const current = await status();
    if (current) return current;
    await sleep(300);
  }
  throw new Error(`Vault local no respondió en ${address}; revisa ${path.relative(root, path.join(state, 'vault.log'))}`);
}

function ensureConfig() {
  mkdirSync(vaultHome, { recursive: true });
  const storagePath = path.join(vaultHome, 'data').replaceAll('\\', '/').replaceAll('"', '\\"');
  writeFileSync(configPath, `storage "file" {\n  path = "${storagePath}"\n}\nlistener "tcp" {\n  address = "127.0.0.1:${port}"\n  tls_disable = true\n}\napi_addr = "${address}"\ndisable_mlock = true\nui = false\n`, { mode: 0o600 });
}

async function startServer() {
  const current = await status();
  if (current) return current;
  const log = openSync(path.join(state, 'vault.log'), 'a');
  const child = spawn(vaultBin, ['server', `-config=${configPath}`], { cwd: root, windowsHide: true, detached: true, stdio: ['ignore', log, log] });
  closeSync(log);
  if (!child.pid) throw new Error('No se pudo iniciar Vault local');
  child.unref();
  writeFileSync(pidPath, String(child.pid));
  return waitForServer();
}

async function initialize(current) {
  let secrets;
  if (!current.initialized) {
    const initialized = JSON.parse(run(['operator', 'init', '-key-shares=1', '-key-threshold=1', '-format=json']));
    secrets = { unsealKey: initialized.unseal_keys_b64[0], rootToken: initialized.root_token };
    writeFileSync(secretsPath, JSON.stringify(secrets, null, 2), { mode: 0o600 });
  } else {
    if (!existsSync(secretsPath)) throw new Error(`Vault ya está inicializado, pero falta ${path.relative(root, secretsPath)}; no se puede desellar sin su clave local.`);
    secrets = readJSON(secretsPath);
  }
  if (current.sealed) await api('', 'POST', 'sys/unseal', { key: secrets.unsealKey });
  return secrets;
}

async function configureTransit(rootToken) {
  const mounts = await api(rootToken, 'GET', 'sys/mounts');
  if (!mounts.data?.[`${mount}/`]) await api(rootToken, 'POST', 'sys/mounts/transit', { type: 'transit' });
  const existing = await fetch(`${address}/v1/${mount}/keys/${kekName}`, { headers: { 'X-Vault-Token': rootToken } });
  if (existing.status === 404) {
    await api(rootToken, 'POST', `${mount}/keys/${kekName}`, { type: 'aes256-gcm96', derived: true, exportable: false });
  } else if (!existing.ok) throw new Error(`No se pudo consultar la KEK local (${existing.status})`);
  else {
    const key = (await existing.json()).data;
    if (key.type !== 'aes256-gcm96' || key.derived !== true || key.exportable !== false) throw new Error('La KEK local existente no cumple aes256-gcm96, derived=true y exportable=false; no se modificó.');
  }
  await api(rootToken, 'PUT', 'sys/policies/acl/hukid-issuer-local', { policy: [
    `path "${mount}/keys/hukid-*" { capabilities = ["create", "read", "update"] }`,
    `path "${mount}/sign/hukid-*" { capabilities = ["update"] }`,
    `path "${mount}/verify/hukid-*" { capabilities = ["update"] }`,
    `path "${mount}/keys/${kekName}" { capabilities = ["read"] }`,
    `path "${mount}/encrypt/${kekName}" { capabilities = ["update"] }`,
    `path "${mount}/decrypt/${kekName}" { capabilities = ["update"] }`,
  ].join('\n') });

  let runtimeToken = '';
  try { runtimeToken = readJSON(runtimePath).token; await api(runtimeToken, 'GET', 'auth/token/lookup-self'); } catch { runtimeToken = ''; }
  if (!runtimeToken) {
    const created = await api(rootToken, 'POST', 'auth/token/create', { policies: ['default', 'hukid-issuer-local'], ttl: '0' });
    runtimeToken = created.auth?.client_token;
  }
  if (!runtimeToken) throw new Error('Vault no devolvió un token runtime');
  writeFileSync(runtimePath, JSON.stringify({ address, token: runtimeToken, mount, kekName }, null, 2), { mode: 0o600 });
}

async function start() {
  if (!existsSync(vaultBin)) throw new Error(`No se encontró Vault en ${path.relative(root, vaultBin)}; instala la versión 1.18.0 en .cache/toolchains/vault-1.18.0 o define HUKID_VAULT_BIN.`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('HUKID_VAULT_PORT inválido');
  mkdirSync(state, { recursive: true });
  ensureConfig();
  const current = await startServer();
  const secrets = await initialize(current);
  await configureTransit(secrets.rootToken);
  console.log(`Vault Transit local listo en ${address}; estado persistente en ${path.relative(root, vaultHome)}.`);
}

function stop() {
  if (!existsSync(pidPath)) { console.log('Vault local no tiene PID registrado; no se detuvo ningún proceso.'); return; }
  const pid = Number(readFileSync(pidPath, 'utf8').trim());
  if (!Number.isInteger(pid) || pid < 1) throw new Error('PID de Vault local inválido');
  const result = spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true, encoding: 'utf8' });
  if (result.status !== 0 && !/not found|no se encontró/i.test(result.stderr || result.stdout || '')) throw new Error('No se pudo detener Vault local');
  console.log('Vault local detenido; su estado persistente se conservó.');
}

const command = process.argv[2];
try {
  if (command === 'start') await start();
  else if (command === 'stop') stop();
  else throw new Error('Uso: node scripts/local-vault.mjs start|stop');
} catch (error) { console.error(error.message); process.exit(1); }
