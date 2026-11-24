import assert from 'node:assert/strict';
import test from 'node:test';
import { wrapStagingClaimsKey } from './wrap-staging-claims-key.mjs';

const values = {
  HUKID_VAULT_ADDR: 'https://vault.staging.example', HUKID_VAULT_TOKEN: 'test-token',
  HUKID_VAULT_MOUNT: 'transit', HUKID_VAULT_KEK_NAME: 'claims-dek',
  HUKID_ISSUANCE_CLAIMS_KEY_VERSION: 'staging-1',
};

test('wraps an in-memory 32-byte DEK using the runtime AAD and returns ciphertext only', async () => {
  let request;
  const ciphertext = await wrapStagingClaimsKey(values, async (url, options) => {
    request = { url: String(url), options, body: JSON.parse(options.body) };
    return { ok: true, json: async () => ({ data: { ciphertext: 'vault:v1:wrapped-value' } }) };
  });
  assert.equal(ciphertext, 'vault:v1:wrapped-value');
  assert.equal(request.url, 'https://vault.staging.example/v1/transit/encrypt/claims-dek');
  assert.equal(request.options.headers['X-Vault-Token'], 'test-token');
  assert.equal(Buffer.from(request.body.plaintext, 'base64').length, 32);
  assert.equal(Buffer.from(request.body.context, 'base64').toString(), 'hukid/claims-dek/v1|staging-1');
});

test('refuses non-HTTPS Vault addresses and unsuccessful Transit responses', async () => {
  await assert.rejects(wrapStagingClaimsKey({ ...values, HUKID_VAULT_ADDR: 'http://vault.example' }), /incompleta o insegura/);
  await assert.rejects(wrapStagingClaimsKey(values, async () => ({ ok: false })), /rechazó/);
  await assert.rejects(wrapStagingClaimsKey({ ...values, HUKID_ISSUANCE_CLAIMS_KEY_CIPHERTEXT: 'vault:v1:existing' }), /no se reemplaza/);
});
