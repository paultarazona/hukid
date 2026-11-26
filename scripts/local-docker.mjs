// Docker Compose backend for the "local" profile outside Windows.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const file = path.join(root, 'deploy', 'local', 'compose.yaml');

// One Compose project (containers and volumes) per state directory.
export function composeFor(state) {
  const project = `hukid-${path.basename(state).toLowerCase().replace(/[^a-z0-9_-]/g, '-')}`;
  return (args, { env = {}, input } = {}) => {
    const r = spawnSync('docker', ['compose', '-f', file, '-p', project, ...args], { cwd: root, encoding: 'utf8', input, env: { ...process.env, ...env } });
    if (r.error || r.status !== 0) throw new Error(`Fallo: docker compose ${args[0]}\n${(r.stderr || r.error?.message || '').trim().split('\n').slice(-3).join('\n')}`);
    return r.stdout;
  };
}
