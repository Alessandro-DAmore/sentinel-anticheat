import { server } from '../src/server.mjs';

const baseUrl = `http://${process.env.SENTINEL_HOST || '127.0.0.1'}:${process.env.SENTINEL_PORT || 8787}`;
const headers = {
  'content-type': 'application/json',
  'x-sentinel-key': process.env.SENTINEL_SERVER_KEY || 'dev_server_replace_me'
};

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const payload = await response.json();

  if (!response.ok) {
    throw new Error(`${path} failed with HTTP ${response.status}: ${JSON.stringify(payload)}`);
  }

  return payload;
}

async function main() {
  await new Promise(resolve => server.listening ? resolve() : server.once('listening', resolve));

  const licenseKey = process.env.SENTINEL_LICENSE_KEY || 'dev_license_replace_me';
  const health = await request('/health');
  const license = await request('/v1/license/verify', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      licenseKey,
      serverId: 'smoke-server'
    })
  });
  const report = await request('/v1/detection/report', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      licenseKey,
      serverId: 'smoke-server',
      playerFingerprint: 'smoke-player',
      detection: 'money_exploit',
      detailHash: 'smoke-detail',
      severity: 85,
      localAction: 'kick',
      framework: 'standalone'
    })
  });

  if (!license.valid) {
    throw new Error('License smoke check returned invalid');
  }

  if (!report.accepted || !report.decision?.signature) {
    throw new Error('Detection smoke check did not return a signed decision');
  }

  console.log(JSON.stringify({
    ok: true,
    health,
    license,
    decision: report.decision
  }, null, 2));
}

try {
  await main();
} finally {
  await new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  });
}
