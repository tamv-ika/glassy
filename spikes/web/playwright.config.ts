import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'tests',
  // Spikes bind fixed ports, so specs must never run concurrently (CONVENTIONS §3).
  workers: 1,
  fullyParallel: false,
  timeout: 60_000,
  use: {
    baseURL: 'http://localhost:8080',
    browserName: 'chromium',
    launchOptions: {
      executablePath: process.env.CHROMIUM_PATH ?? '/opt/pw-browsers/chromium',
      // Resolve every ticket hostname to the local gateway without real DNS.
      args: ['--host-resolver-rules=MAP *.wt.test 127.0.0.1'],
    },
  },
  webServer: {
    command: 'python3 -m http.server 8080 --directory pages',
    url: 'http://localhost:8080/common.js',
    reuseExistingServer: true,
  },
});
