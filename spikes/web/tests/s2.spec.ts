import path from 'node:path';
import { expect, test } from '@playwright/test';
import { K_GS, SPIKES, buildRust, genCert, mintConnectInfo, startProc, startRelay, stopAll } from './procs';

const S2_SERVER = path.join(SPIKES, 's2-webrtc-server/build/s2-webrtc-server');

test.beforeAll(async () => {
  test.setTimeout(180_000);
  buildRust('gw-proto');
  const cert = genCert();
  mintConnectInfo('000000000000000000000000000000a1', cert);
  await startProc(S2_SERVER, [
    '--port', '7101', '--k-gs', K_GS,
    '--cert', path.join(cert.dir, 'cert.pem'), '--key', path.join(cert.dir, 'key.pem'),
  ], 'READY');
  await startRelay('never');
});

test.afterAll(stopAll);

for (const [name, port] of [['direct', 7101], ['via gw-proto', 4443]] as const) {
  test(`S2 ${name}: signaling-less WebRTC data channels`, async ({ page }) => {
    await page.goto('/s2.html');
    const r = await page.evaluate((p) => (window as any).runS2(p), port);
    expect(r.ufragLen).toBe(80);
    expect(r.reliableEcho).toBe('hello-reliable');
    expect(r.unreliableEcho).toBe('hello-unreliable');
  });
}
