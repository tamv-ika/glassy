import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import { SPIKES, GW_PROTO, buildRust, genCert, mintConnectInfo, startProc, startRelay, stopAll } from './procs';

const S1_SERVER = path.join(SPIKES, 'target/debug/s1-wt-server');
const CAPTURE_DIR = path.join(SPIKES, 'gw-proto/tests/fixtures/chromium');

test.beforeAll(async () => {
  test.setTimeout(300_000);
  buildRust('gw-proto');
  buildRust('s1-wt-server');
  // SAN is localhost on purpose: the ticket hostname must work with serverCertificateHashes alone.
  const cert = genCert();
  mintConnectInfo('000000000000000000000000000000a2', cert);
  await startProc(S1_SERVER, [
    '--port', '7102', '--cert', path.join(cert.dir, 'cert.pem'), '--key', path.join(cert.dir, 'key.pem'),
  ], 'READY');
  await startRelay('never');
});

test.afterAll(stopAll);

for (const [name, port] of [['direct', 7102], ['via gw-proto SNI', 4443]] as const) {
  test(`S1 ${name}: hostname URL + serverCertificateHashes`, async ({ page }) => {
    await page.goto('/s1.html');
    const r = await page.evaluate((p) => (window as any).runS1(p), port);
    expect(r.datagramEcho).toBe('ping-dgram');
    expect(r.streamEcho).toBe('ping-stream');
  });
}

test('S1 capture: Chromium Initial datagrams', async ({ page }) => {
  fs.rmSync(CAPTURE_DIR, { recursive: true, force: true });
  await startProc(GW_PROTO, ['capture', '--listen', '127.0.0.1:4444', '--out', CAPTURE_DIR, '--count', '4'], 'READY');
  await page.goto('/s1.html');
  // Nothing answers on 4444, so the connection attempt fails; only the captured datagrams matter.
  await page.evaluate(() => (window as any).runS1(4444).catch(() => null));
  expect(fs.readdirSync(CAPTURE_DIR).length).toBeGreaterThan(0);
});
