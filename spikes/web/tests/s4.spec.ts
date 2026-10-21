import { ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import { SPIKES, buildRust, genCert, mintConnectInfo, procOutput, startProc, startRelay, stopAll } from './procs';

const S4_SERVER = path.join(SPIKES, 's4-wt-ngtcp2/build/s4-wt-server');
let server: ChildProcess;
let settingsLog: string;

test.beforeAll(async () => {
  test.setTimeout(180_000);
  buildRust('gw-proto');
  const cert = genCert();
  mintConnectInfo('000000000000000000000000000000a3', cert);
  settingsLog = path.join(cert.dir, 'settings.json');
  server = await startProc(S4_SERVER, [
    '--port', '7103', '--cert', path.join(cert.dir, 'cert.pem'), '--key', path.join(cert.dir, 'key.pem'),
    '--trusted-cidr', '127.0.0.0/8', '--settings-log', settingsLog,
  ], 'READY');
  await startRelay('always');
});

test.afterAll(stopAll);

async function runS1(page, port: number) {
  await page.goto('/s1.html');
  return page.evaluate((p) => (window as any).runS1(p), port);
}

test('S4 direct: Chromium ↔ ngtcp2 WT', async ({ page }) => {
  const r = await runS1(page, 7103);
  expect(r.datagramEcho).toBe('ping-dgram');
  expect(r.streamEcho).toBe('ping-stream');
});

test('S4 via gw-proto retry=always: no-shared-state token through SNAT', async ({ page }) => {
  const r = await runS1(page, 4443);
  expect(r.datagramEcho).toBe('ping-dgram');
  expect(r.streamEcho).toBe('ping-stream');
  expect(procOutput(server)).toMatch(/retry_token_accepted odcid=[0-9a-f]{16,40}/);
  const log = JSON.parse(fs.readFileSync(settingsLog, 'utf8'));
  expect(log.client_settings.length).toBeGreaterThan(0);
  expect(log.connect_headers[':protocol']).toBe('webtransport');
});
