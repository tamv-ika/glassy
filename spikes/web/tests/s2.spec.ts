import { ChildProcess } from 'node:child_process';
import dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import { K_GS, SPIKES, buildRust, genCert, mintConnectInfo, startProc, startRelay, stopAll } from './procs';

const S2_SERVER = path.join(SPIKES, 's2-webrtc-server/build/s2-webrtc-server');
let server: ChildProcess;

test.beforeAll(async () => {
  test.setTimeout(180_000);
  buildRust('gw-proto');
  const cert = genCert();
  mintConnectInfo('000000000000000000000000000000a1', cert);
  server = await startProc(S2_SERVER, [
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

/** STUN Binding request with USERNAME and an unverifiable MESSAGE-INTEGRITY (RFC 5389). */
function bindingRequest(username: string): Buffer {
  const user = Buffer.from(username);
  const pad = Buffer.alloc((4 - (user.length % 4)) % 4);
  const attrs = Buffer.concat([
    Buffer.from([0x00, 0x06, user.length >> 8, user.length & 0xff]), user, pad,
    Buffer.from([0x00, 0x08, 0x00, 20]), Buffer.alloc(20),
  ]);
  const header = Buffer.alloc(20);
  header.writeUInt16BE(0x0001, 0);
  header.writeUInt16BE(attrs.length, 2);
  header.writeUInt32BE(0x2112a442, 4);
  randomBytes(12).copy(header, 8);
  return Buffer.concat([header, attrs]);
}

test('S2 server survives malformed STUN usernames', async ({ page }) => {
  // Both used to throw inside libjuice's C callback and abort the server.
  const sock = dgram.createSocket('udp4');
  for (const username of ['ab:cdefgh', `${'A'.repeat(80)}:`]) {
    await new Promise<void>((resolve, reject) =>
      sock.send(bindingRequest(username), 7101, '127.0.0.1', (e) => (e ? reject(e) : resolve())));
  }
  sock.close();
  await new Promise((r) => setTimeout(r, 500));
  expect(server.exitCode).toBeNull();
  expect(server.signalCode).toBeNull();

  await page.goto('/s2.html');
  const r = await page.evaluate((p) => (window as any).runS2(p), 7101);
  expect(r.reliableEcho).toBe('hello-reliable');
});
