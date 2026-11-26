// Creates a claims DEK in memory, wraps it with Vault Transit and stores only the
// ciphertext in the gitignored .env.staging.compose file. Never prints the DEK/token.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { parseEnv, render } from './staging-secrets.mjs';

export async function wrapStagingClaimsKey(values, fetchImpl = fetch) {
  if (values.HUKID_ISSUANCE_CLAIMS_KEY_CIPHERTEXT) {
    throw new Error('Ya existe una DEK envuelta; no se reemplaza para evitar perder acceso a datos cifrados');
  }
  const addr = values.HUKID_VAULT_ADDR;
  const token = values.HUKID_VAULT_TOKEN;
  const mount = values.HUKID_VAULT_MOUNT || 'transit';
  const kek = values.HUKID_VAULT_KEK_NAME || 'hukid-claims-dek';
  const version = values.HUKID_ISSUANCE_CLAIMS_KEY_VERSION;
  let base;
  try { base = new URL(addr); } catch { throw new Error('HUKID_VAULT_ADDR debe ser una URL HTTPS'); }
  if (base.protocol !== 'https:' || !base.host || base.username || base.password || base.search || base.hash || !token || !/^[A-Za-z0-9_-]+$/.test(mount) || !/^[A-Za-z0-9_-]+$/.test(kek) || !version) {
    throw new Error('Configuración de Vault Transit incompleta o insegura');
  }
  const dek = randomBytes(32);
  try {
    const headers = { 'Content-Type': 'application/json', 'X-Vault-Token': token };
    if (values.HUKID_VAULT_NAMESPACE) headers['X-Vault-Namespace'] = values.HUKID_VAULT_NAMESPACE;
    const response = await fetchImpl(new URL(`/v1/${mount}/encrypt/${encodeURIComponent(kek)}`, base), {
      method: 'POST', headers, signal: AbortSignal.timeout(10_000),
      body: JSON.stringify({
        plaintext: dek.toString('base64'),
        context: Buffer.from(`hukid/claims-dek/v1|${version}`).toString('base64'),
      }),
    });
    if (!response.ok) throw new Error('Vault Transit rechazó el wrap de la DEK');
    const body = await response.json();
    const ciphertext = body?.data?.ciphertext;
    if (typeof ciphertext !== 'string' || !/^vault:v[1-9][0-9]*:.+$/.test(ciphertext)) throw new Error('Respuesta de Vault Transit inválida');
    return ciphertext;
  } finally {
    dek.fill(0);
  }
}

export async function main(root = process.cwd(), fetchImpl = fetch) {
  const target = `${root}/.env.staging.compose`;
  if (!existsSync(target)) throw new Error('Primero ejecuta node scripts/staging-secrets.mjs');
  const values = parseEnv(readFileSync(target, 'utf8'));
  values.HUKID_ISSUANCE_CLAIMS_KEY_CIPHERTEXT = await wrapStagingClaimsKey(values, fetchImpl);
  writeFileSync(target, render(values), { mode: 0o600 });
  console.log('DEK envuelta y guardada en HUKID_ISSUANCE_CLAIMS_KEY_CIPHERTEXT; no se mostró la clave en claro.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { await main(); } catch (error) { console.error(error.message); process.exit(1); }
}
