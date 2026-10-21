import { ChildProcess, execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Fixed keys shared by every spike; never used outside spikes/.
export const K_GW = '11'.repeat(16);
export const K_GS = '22'.repeat(32);
export const RETRY_KEY = '33'.repeat(32);

export const SPIKES = path.resolve(__dirname, '../..');
export const GW_PROTO = path.join(SPIKES, 'target/debug/gw-proto');
export const PAGES = path.join(SPIKES, 'web/pages');
export const BACKENDS = path.join(SPIKES, 'web/fixtures/backends.json');

const running: ChildProcess[] = [];
const outputs = new Map<ChildProcess, string>();

/** Spawns a long-running process and resolves once its stdout contains `readyLine`. */
export function startProc(cmd: string, args: string[], readyLine: string): Promise<ChildProcess> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    running.push(child);
    outputs.set(child, '');
    const timer = setTimeout(() => reject(new Error(`${cmd}: no "${readyLine}" within 30s`)), 30_000);
    const collect = (chunk: Buffer) => {
      const text = outputs.get(child)! + chunk.toString();
      outputs.set(child, text);
      if (text.includes(readyLine)) {
        clearTimeout(timer);
        resolve(child);
      }
    };
    child.stdout!.on('data', collect);
    child.stderr!.on('data', collect);
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`${cmd} exited with ${code} before ready:\n${outputs.get(child)}`));
    });
  });
}

/** Combined stdout and stderr captured so far. */
export function procOutput(child: ChildProcess): string {
  return outputs.get(child) ?? '';
}

export async function stopAll(): Promise<void> {
  for (const child of running.splice(0)) {
    child.kill('SIGTERM');
  }
}

/** Builds the Rust spike binaries so tests never run a stale gateway. */
export function buildRust(pkg: string): void {
  execFileSync('cargo', ['build', '-q', '-p', pkg], { cwd: SPIKES, stdio: 'inherit' });
}

export function genCert(): { dir: string; fp: string; sha256: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'glassy-cert-'));
  execFileSync('bash', [path.join(SPIKES, 'web/fixtures/gen-cert.sh'), dir]);
  return {
    dir,
    fp: fs.readFileSync(path.join(dir, 'cert.fp'), 'utf8').trim(),
    sha256: fs.readFileSync(path.join(dir, 'cert.sha256'), 'utf8').trim(),
  };
}

/** Mints a ConnectInfo for `serverId` and publishes it to the test pages as /connect.json. */
export function mintConnectInfo(serverId: string, cert: { fp: string; sha256: string }): void {
  const json = execFileSync(GW_PROTO, [
    'mint', '--k-gw', K_GW, '--key-id', '1', '--k-gs', K_GS, '--server-id', serverId,
    '--transports', 'webrtc,webtransport', '--expiry-secs', '3600', '--gateway', '127.0.0.1:4443',
    '--sni-suffix', 'wt.test', '--dtls-fp', cert.fp, '--cert-sha256', cert.sha256,
  ]);
  fs.writeFileSync(path.join(PAGES, 'connect.json'), json);
}

export function startRelay(retry: 'always' | 'never'): Promise<ChildProcess> {
  return startProc(GW_PROTO, [
    'relay', '--listen', '127.0.0.1:4443', '--k-gw', K_GW, '--key-id', '1', '--backends', BACKENDS,
    '--retry', retry, '--retry-key', RETRY_KEY, '--sni-suffix', 'wt.test',
  ], 'READY');
}
