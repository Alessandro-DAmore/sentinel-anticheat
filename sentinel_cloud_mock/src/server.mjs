import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import PDFDocument from 'pdfkit';
import {
  createDecipheriv,
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual
} from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, '..');
const downloadsDir = path.join(packageRoot, 'downloads');
const assetsDir = path.join(packageRoot, 'assets');
const dataDir = path.join(packageRoot, 'data');
const signaturesPath = path.join(dataDir, 'signatures.json');
const downloadManifestPath = path.join(dataDir, 'download-manifest.json');

const host = process.env.SENTINEL_HOST || '127.0.0.1';
const port = Number(process.env.PORT || process.env.SENTINEL_PORT || 8787);
const publicBaseUrl = (process.env.SENTINEL_PUBLIC_BASE_URL || `http://${host}:${port}`).replace(/\/$/, '');
const sharedSecret = process.env.SENTINEL_SHARED_SECRET || 'CHANGE_ME_SENTINEL_SHARED_SECRET';
const licenseKeys = new Set((process.env.SENTINEL_LICENSE_KEYS || 'CHANGE_ME_SENTINEL_LICENSE').split(','));
const serverKeys = new Set((process.env.SENTINEL_SERVER_KEYS || 'CHANGE_ME_SENTINEL_SERVER_KEY').split(','));
const dashboardToken = process.env.SENTINEL_DASHBOARD_TOKEN || 'CHANGE_ME_DASHBOARD_TOKEN';
const adminUser = process.env.SENTINEL_ADMIN_USER || 'admin';
const adminPassword = process.env.SENTINEL_ADMIN_PASSWORD || 'CHANGE_ME_ADMIN_PASSWORD';
const discordClientId = process.env.DISCORD_CLIENT_ID || '';
const discordClientSecret = process.env.DISCORD_CLIENT_SECRET || '';
const discordRedirectUri = process.env.DISCORD_REDIRECT_URI || `${publicBaseUrl}/auth/discord/callback`;
const discordOAuthConfigured = Boolean(discordClientId && discordClientSecret);
const maxBodyBytes = Number(process.env.SENTINEL_MAX_BODY_BYTES || 10_000_000);
const sessionTtlMs = Number(process.env.SENTINEL_SESSION_TTL_MS || 15_000);
const blockedSessionTtlMs = Number(process.env.SENTINEL_BLOCKED_SESSION_TTL_MS || 300_000);
const storageProvider = String(process.env.SENTINEL_STORAGE_PROVIDER || 'local').toLowerCase();
const r2Bucket = process.env.SENTINEL_R2_BUCKET || '';
const r2AccountId = process.env.SENTINEL_R2_ACCOUNT_ID || '';
const r2AccessKeyId = process.env.SENTINEL_R2_ACCESS_KEY_ID || '';
const r2SecretAccessKey = process.env.SENTINEL_R2_SECRET_ACCESS_KEY || '';
const r2PublicBaseUrl = (process.env.SENTINEL_R2_PUBLIC_BASE_URL || '').replace(/\/$/, '');
const storagePrefix = String(process.env.SENTINEL_STORAGE_PREFIX || 'downloads')
  .replace(/^\/+|\/+$/g, '')
  .replace(/\\/g, '/');
const cloudStorageEnabled = storageProvider === 'r2'
  && r2Bucket
  && r2AccountId
  && r2AccessKeyId
  && r2SecretAccessKey;
const r2Client = cloudStorageEnabled
  ? new S3Client({
      region: 'auto',
      endpoint: `https://${r2AccountId}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: r2AccessKeyId,
        secretAccessKey: r2SecretAccessKey
      }
    })
  : null;

fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(downloadsDir, { recursive: true });

const events = [];
const agentReports = [];
const banReports = [];
const agentSessions = new Map();
const discordLinks = new Map();
const oauthStates = new Map();

function stableHash(input, seed = 5381) {
  let hash = seed >>> 0;
  for (let index = 0; index < input.length; index += 1) {
    hash = (((hash * 33) >>> 0) + input.charCodeAt(index)) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

function fingerprint(value) {
  const input = String(value || '');
  return [
    stableHash(input, 5381),
    stableHash([...input].reverse().join(''), 52711),
    stableHash(`${input}:sentinel`, 1315423911),
    stableHash(`sentinel:${input}`, 2654435761)
  ].join('');
}

function sha256(input) {
  return createHash('sha256').update(String(input)).digest();
}

function hmacHex(input) {
  return createHmac('sha256', sha256(sharedSecret)).update(String(input)).digest('hex');
}

function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex');
}

function readSignatureFeed() {
  const dataRaw = fs.existsSync(signaturesPath)
    ? fs.readFileSync(signaturesPath, 'utf8')
    : JSON.stringify({
        version: 'empty',
        knownBadSha256: [],
        suspiciousNames: [],
        suspiciousPaths: [],
        suspiciousDrivers: [],
        runtimeMarkers: []
      });
  const data = JSON.parse(dataRaw);
  return {
    data,
    dataRaw,
    hmac: hmacHex(dataRaw)
  };
}

function publicIpFromRequest(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  return String(raw || req.socket.remoteAddress || '')
    .split(',')[0]
    .trim()
    .replace(/^::ffff:/, '');
}

function normalizeDiscordId(value) {
  return String(value || '')
    .replace(/^discord:/i, '')
    .replace(/[^\d]/g, '')
    .trim();
}

function activeBanForIdentity({ discordId, machineFingerprint, publicIp, localIps = [] }) {
  const normalizedDiscordId = normalizeDiscordId(discordId);
  const machine = String(machineFingerprint || '');
  const networkIp = String(publicIp || '');
  const localSet = new Set((Array.isArray(localIps) ? localIps : []).map(item => String(item || '')).filter(Boolean));

  return banReports.find(item => {
    if (!item.active) return false;
    if (normalizedDiscordId && item.discordId === normalizedDiscordId) return true;
    if (machine && item.machineFingerprint === machine) return true;
    if (networkIp && item.publicIp === networkIp) return true;
    if (Array.isArray(item.localIps) && item.localIps.some(ip => localSet.has(String(ip)))) return true;
    return false;
  }) || null;
}

function banDecisionPayload(ban) {
  if (!ban) {
    return {
      allowed: true,
      banned: false,
      action: 'allow'
    };
  }

  return {
    allowed: false,
    banned: true,
    action: 'block',
    banId: ban.id,
    reportId: ban.reportId,
    reason: ban.reason || 'banned_by_sentinel',
    message: `Sentinel Anticheat: sei bannato. Ban ID ${ban.id}. Motivo: ${ban.reason || 'banned_by_sentinel'}`
  };
}

function activeSessionForDiscord(discordId) {
  const normalized = normalizeDiscordId(discordId);
  const now = Date.now();
  for (const session of agentSessions.values()) {
    if (
      session.discordId === normalized &&
      session.status === 'active' &&
      now - session.lastSeenAt <= sessionTtlMs
    ) {
      return session;
    }
  }
  return null;
}

function blockedSessionForDiscord(discordId) {
  const normalized = normalizeDiscordId(discordId);
  const now = Date.now();
  for (const session of agentSessions.values()) {
    if (
      session.discordId === normalized &&
      session.status === 'blocked' &&
      now - session.lastSeenAt <= blockedSessionTtlMs
    ) {
      return session;
    }
  }
  return null;
}

function markSessionBlocked(payload, reason = 'suspicious_scan_blocked') {
  const sessionId = String(payload.sessionId || '');
  let session = sessionId ? agentSessions.get(sessionId) : null;
  const discordId = normalizeDiscordId(payload.discordId);

  if (!session && discordId) {
    session = activeSessionForDiscord(discordId);
  }

  if (!session) {
    return null;
  }

  session.status = 'blocked';
  session.blockReason = reason;
  session.lastSeenAt = Date.now();
  session.lastHeartbeat = new Date().toISOString();
  return session;
}

function decryptEnvelope(envelope) {
  if (!envelope || envelope.alg !== 'AES-256-CBC-HMAC-SHA256') {
    throw new Error('unsupported_envelope');
  }

  const key = sha256(sharedSecret);
  const iv = Buffer.from(String(envelope.iv || ''), 'base64');
  const ciphertext = Buffer.from(String(envelope.ciphertext || ''), 'base64');
  const expected = Buffer.from(String(envelope.hmac || ''), 'base64');
  const actual = createHmac('sha256', key)
    .update(Buffer.concat([iv, ciphertext]))
    .digest();

  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    throw new Error('invalid_envelope_hmac');
  }

  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  return JSON.parse(plaintext);
}

function decisionSignature(decision) {
  const canonical = [
    decision.action || '',
    decision.reason || '',
    decision.confidence || '',
    decision.nonce || ''
  ].join('|');

  return fingerprint(`${sharedSecret}:decision:${canonical}`);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let tooLarge = false;
    req.on('data', chunk => {
      if (tooLarge) {
        return;
      }
      body += chunk;
      if (Buffer.byteLength(body, 'utf8') > maxBodyBytes) {
        tooLarge = true;
        body = '';
      }
    });
    req.on('end', () => {
      if (tooLarge) {
        const error = new Error('body_too_large');
        error.code = 'body_too_large';
        reject(error);
        return;
      }
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(error);
      }
    });
  });
}

function writeJson(res, status, payload) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store'
  });
  res.end(JSON.stringify(payload));
}

function writeHtml(res, status, html) {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store'
  });
  res.end(html);
}

function writeText(res, status, text) {
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store'
  });
  res.end(text);
}

function baseDownloadBuilds() {
  return [
    {
      platform: 'x64',
      label: 'Windows 64 bit',
      route: '/download/windows-x64',
      filename: 'SentinelAnticheat-Windows-x64.exe',
      downloadName: 'Sentinel Anticheat.exe'
    },
    {
      platform: 'x86',
      label: 'Windows 32 bit',
      route: '/download/windows-x86',
      filename: 'SentinelAnticheat-Windows-x86.exe',
      downloadName: 'Sentinel Anticheat 32 bit.exe'
    }
  ];
}

function localDownloadBuilds(manifest = {}) {
  return baseDownloadBuilds().map(build => {
    const manifestBuild = manifest.builds?.[build.platform] || {};
    const filePath = path.join(downloadsDir, build.filename);
    const exists = fs.existsSync(filePath);
    const stat = exists ? fs.statSync(filePath) : null;
    const publicUrl = cloudPublicUrl(build.filename);
    return {
      ...build,
      available: Boolean(manifestBuild.uploadedAt || exists),
      storage: cloudStorageEnabled ? 'Cloudflare R2' : 'local',
      publicUrl,
      sha256: manifestBuild.sha256 || null,
      sizeBytes: manifestBuild.sizeBytes || stat?.size || 0,
      updatedAt: manifestBuild.uploadedAt || stat?.mtime.toISOString() || null
    };
  });
}

async function objectBodyToBuffer(body) {
  if (!body) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);
  if (typeof body.transformToByteArray === 'function') {
    return Buffer.from(await body.transformToByteArray());
  }
  if (typeof body.pipe === 'function') {
    return await new Promise((resolve, reject) => {
      const chunks = [];
      body.on('data', chunk => chunks.push(Buffer.from(chunk)));
      body.on('error', reject);
      body.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }
  return Buffer.from(String(body));
}

function emptyDownloadManifest() {
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    storage: cloudStorageEnabled ? 'Cloudflare R2' : 'local',
    builds: {}
  };
}

function readLocalDownloadManifest() {
  try {
    return fs.existsSync(downloadManifestPath)
      ? JSON.parse(fs.readFileSync(downloadManifestPath, 'utf8'))
      : emptyDownloadManifest();
  } catch {
    return emptyDownloadManifest();
  }
}

async function readDownloadManifest() {
  if (cloudStorageEnabled) {
    try {
      const object = await r2Client.send(new GetObjectCommand({
        Bucket: r2Bucket,
        Key: downloadObjectKey('manifest.json')
      }));
      return JSON.parse((await objectBodyToBuffer(object.Body)).toString('utf8'));
    } catch {
      return readLocalDownloadManifest();
    }
  }
  return readLocalDownloadManifest();
}

async function writeDownloadManifest(manifest) {
  const nextManifest = {
    ...manifest,
    version: 1,
    generatedAt: new Date().toISOString(),
    storage: cloudStorageEnabled ? 'Cloudflare R2' : 'local'
  };
  const raw = JSON.stringify(nextManifest, null, 2);
  fs.writeFileSync(downloadManifestPath, `${raw}\n`, 'utf8');

  if (cloudStorageEnabled) {
    await r2Client.send(new PutObjectCommand({
      Bucket: r2Bucket,
      Key: downloadObjectKey('manifest.json'),
      Body: raw,
      ContentType: 'application/json; charset=utf-8',
      CacheControl: 'no-store'
    }));
  }

  return nextManifest;
}

async function downloadBuilds() {
  return localDownloadBuilds(await readDownloadManifest());
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value} B`;
}

function downloadObjectKey(filename) {
  const safeName = path.basename(filename);
  return storagePrefix ? `${storagePrefix}/${safeName}` : safeName;
}

function cloudPublicUrl(filename) {
  if (!r2PublicBaseUrl) return '';
  return `${r2PublicBaseUrl}/${downloadObjectKey(filename).split('/').map(encodeURIComponent).join('/')}`;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function logoImage(className = 'brand-logo') {
  return `<img class="${className}" src="/assets/sentinel-logo.png" alt="Sentinel Anticheat logo">`;
}

function siteStyle() {
  return `<style>
    @font-face {
      font-family: SentinelUI;
      src: url('/assets/bahnschrift.ttf') format('truetype');
      font-display: swap;
    }
    :root {
      color-scheme: dark;
      --bg:#02070d;
      --bg2:#07111b;
      --panel:#07111b;
      --panel2:#0b1825;
      --line:#1d344d;
      --line2:#2f536f;
      --text:#edf5ff;
      --muted:#9cafbf;
      --accent:#0099ff;
      --accent2:#6fbdf2;
      --danger:#ff5d68;
      --warn:#ffd166;
      --ok:#52e0a4;
      --metal:#d9e1ea;
      --silver:#aeb8c3;
    }
    * { box-sizing:border-box; }
    html { scroll-behavior:smooth; }
    body { margin:0; background:var(--bg); color:var(--text); font:15px/1.55 SentinelUI, Bahnschrift, "Segoe UI", system-ui, sans-serif; }
    body::before {
      content:""; position:fixed; inset:0; pointer-events:none; opacity:.45;
      background-image:
        radial-gradient(circle at 68% 16%, rgba(0,153,255,.16), transparent 32%),
        linear-gradient(rgba(0,153,255,.055) 1px, transparent 1px),
        linear-gradient(90deg, rgba(174,184,195,.045) 1px, transparent 1px);
      background-size:auto, 48px 48px, 48px 48px;
      mask-image:linear-gradient(to bottom, #000, transparent 84%);
    }
    a { color:inherit; text-decoration:none; }
    .wrap { width:min(1200px, calc(100% - 44px)); margin:0 auto; position:relative; }
    .topbar { position:sticky; top:0; z-index:3; border-bottom:1px solid rgba(99,143,177,.28); background:rgba(2,7,13,.88); backdrop-filter:blur(18px); }
    .nav { min-height:76px; display:flex; align-items:center; justify-content:space-between; gap:22px; }
    .brand { display:flex; align-items:center; gap:13px; font-weight:800; font-size:18px; letter-spacing:.01em; }
    .brand-logo { width:42px; height:42px; object-fit:contain; border-radius:0; filter:drop-shadow(0 0 16px rgba(0,153,255,.22)); }
    .logo-stage { display:grid; place-items:center; min-height:440px; border:1px solid rgba(47,83,111,.75); border-radius:18px; background:radial-gradient(circle at 50% 45%, rgba(0,153,255,.16), transparent 32%), linear-gradient(135deg,rgba(7,17,27,.78),rgba(4,10,17,.42)); box-shadow:0 32px 80px rgba(0,0,0,.38); }
    .hero-mark { width:min(390px, 86vw); aspect-ratio:1; object-fit:contain; filter:drop-shadow(0 30px 46px rgba(0,0,0,.55)) drop-shadow(0 0 38px rgba(0,153,255,.18)); }
    .brand span { color:var(--muted); font-weight:500; font-size:11px; text-transform:uppercase; letter-spacing:.16em; display:block; }
    .links { display:flex; align-items:center; gap:10px; }
    .links a, .button { display:inline-flex; align-items:center; justify-content:center; border:1px solid var(--line); background:linear-gradient(180deg,#0b1724,#07101a); border-radius:10px; padding:10px 15px; color:#dceaff; min-height:42px; }
    .links a:hover, .button:hover { border-color:var(--line2); background:linear-gradient(180deg,#102338,#091522); }
    .button.primary { background:linear-gradient(180deg,#1aa8ff,#006ebf); color:#f5fbff; border-color:#1d9df0; font-weight:800; box-shadow:0 0 24px rgba(0,153,255,.22); }
    .button.ghost { background:transparent; }
    .hero { min-height:calc(100vh - 76px); display:grid; align-items:center; padding:64px 0 72px; }
    .hero-grid { display:grid; grid-template-columns:minmax(0,1.05fr) minmax(340px,.95fr); gap:42px; align-items:center; }
    .eyebrow { color:var(--accent); text-transform:uppercase; font-weight:800; letter-spacing:.18em; font-size:12px; }
    h1 { font-size:clamp(44px, 6.2vw, 82px); line-height:.96; margin:14px 0 18px; letter-spacing:0; }
    h2 { font-size:30px; margin:0 0 10px; letter-spacing:0; }
    p { color:var(--muted); margin:0; }
    .hero-copy { font-size:18px; max-width:690px; color:#b8c9d8; }
    .actions { display:flex; flex-wrap:wrap; gap:12px; margin-top:28px; }
    .metric-row { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin-top:28px; max-width:720px; }
    .metric { border:1px solid var(--line); background:rgba(7,17,27,.76); border-radius:12px; padding:14px; }
    .metric b { display:block; color:var(--text); font-size:24px; line-height:1; }
    .metric span { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
    .value { color:var(--accent); font-size:42px; font-weight:800; line-height:1; margin-top:12px; }
    .console {
      border:1px solid var(--line); background:linear-gradient(180deg,#0d1621,#060a10); border-radius:14px; overflow:hidden;
      box-shadow:0 22px 70px rgba(0,0,0,.36);
    }
    .console-head { height:42px; display:flex; align-items:center; gap:7px; padding:0 14px; border-bottom:1px solid var(--line); color:var(--muted); }
    .dot { width:10px; height:10px; border-radius:999px; background:var(--accent); }
    .dot:nth-child(2) { background:var(--warn); } .dot:nth-child(3) { background:var(--danger); }
    .console-body { padding:18px; font-family:"Cascadia Mono", Consolas, monospace; font-size:13px; min-height:310px; }
    .line { display:flex; gap:10px; padding:6px 0; border-bottom:1px solid rgba(255,255,255,.04); }
    .line b { color:var(--accent); min-width:92px; }
    .section { padding:64px 0; border-top:1px solid rgba(99,143,177,.2); background:rgba(7,12,18,.62); }
    .section-head { max-width:760px; margin-bottom:24px; }
    .grid3 { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; }
    .card, .panel { border:1px solid var(--line); background:linear-gradient(180deg,rgba(13,22,32,.96),rgba(6,13,21,.96)); border-radius:14px; padding:20px; box-shadow:0 18px 46px rgba(0,0,0,.24); }
    .card h3 { margin:0 0 8px; font-size:18px; }
    .card .num { color:var(--accent); font-size:13px; letter-spacing:.14em; font-weight:800; margin-bottom:10px; }
    .download-grid, .admin-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; }
    input { width:100%; border:1px solid var(--line); border-radius:10px; background:#050a10; color:var(--text); padding:13px; margin:6px 0 12px; font:inherit; }
    label { color:#c7d6e4; font-weight:650; font-size:12px; }
    table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:12px; overflow:hidden; }
    th, td { padding:12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
    th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
    code { color:#d9f7ff; overflow-wrap:anywhere; }
    .badge { display:inline-flex; align-items:center; border:1px solid var(--line); border-radius:999px; padding:4px 8px; color:#cfe1f1; background:#0a121b; }
    .badge.danger { border-color:rgba(255,93,104,.45); color:#ffd1d4; }
    .finding { display:grid; grid-template-columns:120px minmax(170px,1fr) minmax(220px,1.5fr); gap:10px; padding:10px 0; border-top:1px solid var(--line); }
    .timeline { display:grid; gap:12px; }
    .timeline div { border-left:2px solid var(--accent); padding:2px 0 2px 14px; color:var(--muted); }
    .split { display:grid; grid-template-columns:minmax(0,.92fr) minmax(320px,1.08fr); gap:28px; align-items:start; }
    .muted { color:var(--muted); }
    .footer { padding:28px 0; color:var(--muted); border-top:1px solid var(--line); }
    @media (max-width:840px) {
      .hero-grid, .grid3, .split, .metric-row { grid-template-columns:1fr; }
      .links { flex-wrap:wrap; justify-content:flex-end; }
      .nav { height:auto; padding:12px 0; align-items:flex-start; }
      .finding { grid-template-columns:1fr; }
    }
  </style>`;
}

function layoutPage({ title, active = '', body }) {
  return `<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} - Sentinel Anticheat</title>
  ${siteStyle()}
</head>
<body>
  <header class="topbar">
    <nav class="wrap nav">
      <a class="brand" href="/">
        ${logoImage('brand-logo')}
        <div>Sentinel Anticheat<span>FiveM desktop protection</span></div>
      </a>
      <div class="links">
        <a href="/" ${active === 'home' ? 'class="button primary"' : ''}>Home</a>
        <a href="/download" ${active === 'download' ? 'class="button primary"' : ''}>Download</a>
        <a href="/verify" ${active === 'verify' ? 'class="button primary"' : ''}>Verifica</a>
        <a href="/admin" ${active === 'admin' ? 'class="button primary"' : ''}>Admin</a>
      </div>
    </nav>
  </header>
  ${body}
  <footer class="footer"><div class="wrap">Sentinel Anticheat local dev build. Report cifrati, file personali non caricati.</div></footer>
</body>
</html>`;
}

function homeHtml() {
  return layoutPage({
    title: 'Home',
    active: 'home',
    body: `<main class="hero">
  <div class="wrap hero-grid">
    <section>
      <div class="eyebrow">Protecting fair play</div>
      <h1>Sentinel Anticheat</h1>
      <p class="hero-copy">Client anticheat desktop per server FiveM: collega l'identita Discord, verifica l'ambiente locale, mantiene una sessione live durante il gioco e genera report tecnici leggibili dallo staff.</p>
      <div class="actions">
        <a class="button primary" href="/download">Scarica l'app</a>
        <a class="button ghost" href="/admin">Area Admin</a>
      </div>
      <div class="metric-row">
        <div class="metric"><b>Live</b><span>Heartbeat client</span></div>
        <div class="metric"><b>PDF</b><span>Report staff</span></div>
        <div class="metric"><b>Discord</b><span>Identity link</span></div>
      </div>
    </section>
    <aside class="logo-stage" aria-label="Sentinel Anticheat logo">
      ${logoImage('hero-mark')}
    </aside>
  </div>
</main>
<section class="section">
  <div class="wrap">
    <div class="section-head">
      <div class="eyebrow">Sistema anticheat</div>
      <h2>Controllo locale, decisioni server-side, report chiari.</h2>
      <p>Sentinel separa i dati sensibili dal lavoro dello staff: il client invia report cifrati e l'admin vede solo informazioni utili alla revisione.</p>
    </div>
    <div class="grid3">
      <article class="card"><div class="num">01</div><h3>Discord-first</h3><p>Ogni report lega il controllo al Discord ID del player, cosi lo staff sa chi deve verificare.</p></article>
      <article class="card"><div class="num">02</div><h3>Sessione obbligatoria</h3><p>Il resource FiveM verifica che il client Sentinel resti aperto; se la sessione sparisce, il player viene espulso.</p></article>
      <article class="card"><div class="num">03</div><h3>Runtime guard</h3><p>Dopo il controllo iniziale, Sentinel continua a monitorare segnali sospetti mentre il player e' in gioco.</p></article>
      <article class="card"><div class="num">04</div><h3>Report cybersecurity</h3><p>Lo staff riceve severita, motivazione, path normalizzato, hash e dati tecnici in un PDF ordinato.</p></article>
      <article class="card"><div class="num">05</div><h3>Privacy by design</h3><p>I file personali non vengono caricati: Sentinel registra metadati, hash e indicatori necessari alla revisione.</p></article>
      <article class="card"><div class="num">06</div><h3>Ban review</h3><p>Gli admin possono cercare report, consultare ban e gestire eventuali errori direttamente dal pannello.</p></article>
    </div>
  </div>
</section>
<section class="section">
  <div class="wrap split">
    <div>
      <div class="eyebrow">Flow operativo</div>
      <h2>Dal click su Connetti alla verifica in server.</h2>
      <p>Il client non e' solo una finestra: diventa una sessione autorizzata che il server FiveM controlla a intervalli regolari.</p>
    </div>
    <div class="timeline">
      <div><b>Login Discord</b><br>Il player collega l'account prima della connessione.</div>
      <div><b>Scan locale</b><br>Processi, servizi, driver e percorsi sensibili vengono verificati.</div>
      <div><b>Sessione cloud</b><br>Il server riceve heartbeat e stato live del client.</div>
      <div><b>Report admin</b><br>Solo se c'e' un sospetto viene generato un report consultabile.</div>
    </div>
  </div>
</section>`
  });
}

async function downloadHtml() {
  const builds = await downloadBuilds();
  const buildCards = builds.map(build => `
      <article class="panel">
        <div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start">
          <div>
            <h2>${escapeHtml(build.label)}</h2>
            <p>${build.platform === 'x64'
              ? "Consigliato per la maggior parte dei PC moderni. Scarica direttamente l'app Sentinel Anticheat con icona ufficiale."
              : "Compatibilita legacy per PC piu vecchi. Scarica direttamente l'eseguibile Windows."}</p>
          </div>
          <span class="badge ${build.available ? '' : 'danger'}">${build.available ? 'Disponibile' : 'Da caricare'}</span>
        </div>
        <p class="muted" style="margin-top:14px">${build.available
          ? `File: ${escapeHtml(build.downloadName)}${build.sizeBytes ? ` - ${formatBytes(build.sizeBytes)}` : ''} - Storage: ${escapeHtml(build.storage)}`
          : 'La build non e ancora presente sul server online.'}</p>
        ${build.sha256 ? `<p class="muted" style="margin-top:10px">SHA256</p><code>${escapeHtml(build.sha256)}</code>` : ''}
        <div class="actions">
          ${build.available
            ? `<a class="button ${build.platform === 'x64' ? 'primary' : ''}" href="${build.route}">Scarica app ${build.platform === 'x64' ? '64 bit' : '32 bit'}</a>`
            : '<a class="button ghost" href="/admin">Carica da Admin</a>'}
          <a class="button ghost" href="/verify">Verifica hash</a>
        </div>
      </article>
  `).join('');

  return layoutPage({
    title: 'Download',
    active: 'download',
    body: `<main class="section">
  <div class="wrap">
    <div class="eyebrow">Windows client</div>
    <h1>Scarica Sentinel Anticheat</h1>
    <p class="hero-copy">Scarica l'app Windows ufficiale. Al primo avvio collega Discord, esegue la verifica locale e mantiene la sessione anticheat attiva durante la permanenza nel server.</p>
    <div class="download-grid" style="margin-top:26px">${buildCards}</div>
    <div class="panel" style="margin-top:18px">
      <div class="eyebrow">Sicurezza download</div>
      <h2>Firma digitale e SmartScreen</h2>
      <p>La build locale e' pronta per essere firmata. In produzione Sentinel dovra usare un certificato Code Signing valido: e' il modo corretto per far riconoscere a Windows publisher, integrita e attendibilita dell'app.</p>
    </div>
  </div>
</main>`
  });
}

async function verifyHtml() {
  const builds = await downloadBuilds();
  const cards = builds.map(build => {
    const command = `Get-FileHash -Algorithm SHA256 -LiteralPath "$env:USERPROFILE\\Downloads\\${build.downloadName}"`;
    return `<article class="panel">
      <div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start">
        <div>
          <h2>${escapeHtml(build.label)}</h2>
          <p class="muted">${escapeHtml(build.downloadName)}${build.sizeBytes ? ` - ${formatBytes(build.sizeBytes)}` : ''}</p>
        </div>
        <span class="badge ${build.sha256 ? '' : 'danger'}">${build.sha256 ? 'Hash disponibile' : 'Hash mancante'}</span>
      </div>
      <p class="muted" style="margin-top:16px">SHA256 ufficiale</p>
      <code>${escapeHtml(build.sha256 || 'Non ancora generato')}</code>
      <p class="muted" style="margin-top:16px">Comando PowerShell</p>
      <code>${escapeHtml(command)}</code>
      <div class="actions">
        <a class="button ${build.platform === 'x64' ? 'primary' : ''}" href="${build.route}">Scarica</a>
      </div>
    </article>`;
  }).join('');

  return layoutPage({
    title: 'Verifica Download',
    active: 'verify',
    body: `<main class="section">
  <div class="wrap">
    <div class="eyebrow">Download integrity</div>
    <h1>Verifica download</h1>
    <p class="hero-copy">Confronta lo SHA256 del file scaricato con quello ufficiale pubblicato da Sentinel. Se non coincidono, elimina il file e riscaricalo dal sito ufficiale.</p>
    <div class="download-grid" style="margin-top:26px">${cards}</div>
    <div class="panel" style="margin-top:18px">
      <div class="eyebrow">Nota firma digitale</div>
      <h2>Firma pronta, certificato non ancora attivo</h2>
      <p>Questa verifica non sostituisce la firma Code Signing, ma rende controllabile l'integrita della build fino a quando non sara disponibile un certificato riconosciuto da Windows.</p>
    </div>
  </div>
</main>`
  });
}

function adminLoginHtml() {
  return layoutPage({
    title: 'Admin Login',
    active: 'admin',
    body: `<main class="section">
  <div class="wrap admin-grid">
    <section>
      <div class="eyebrow">Secure staff access</div>
      <h1>Area Admin</h1>
      <p class="hero-copy">Inserisci le credenziali per aprire report utenti, ban e PDF di revisione.</p>
    </section>
    <form class="panel" id="loginForm">
      <label>Username</label>
      <input name="username" autocomplete="username" value="">
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password">
      <button class="button primary" type="submit">Accedi</button>
      <p class="muted" id="loginMsg" style="margin-top:12px">Build locale: credenziali dev configurabili via env.</p>
    </form>
  </div>
</main>
<script>
  document.getElementById('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const response = await fetch('/v1/admin/login', {
      method:'POST',
      headers:{'content-type':'application/json'},
      body: JSON.stringify({ username: form.get('username'), password: form.get('password') })
    });
    const data = await response.json();
    if (!response.ok) {
      document.getElementById('loginMsg').textContent = 'Credenziali non valide.';
      return;
    }
    location.href = '/admin/panel?token=' + encodeURIComponent(data.token);
  });
</script>`
  });
}

function adminShell({ title, token, body }) {
  return layoutPage({
    title,
    active: 'admin',
    body: `<main class="section">
  <div class="wrap">
    <div class="links" style="justify-content:flex-start; margin-bottom:18px">
      <a class="button primary" href="/admin/panel?token=${encodeURIComponent(token)}">Overview</a>
      <a class="button" href="/admin/reports?token=${encodeURIComponent(token)}">Report</a>
      <a class="button" href="/admin/bans?token=${encodeURIComponent(token)}">Ban</a>
    </div>
    ${body}
  </div>
</main>`
  });
}

async function adminPanelHtml(token) {
  const activeSessions = [...agentSessions.values()].filter(session => Date.now() - session.lastSeenAt <= sessionTtlMs).length;
  const suspiciousReports = agentReports.filter(isReportSuspicious);
  const builds = await downloadBuilds();
  const buildRows = builds.map(build => `
    <tr>
      <td>${escapeHtml(build.label)}</td>
      <td><span class="badge ${build.available ? '' : 'danger'}">${build.available ? 'online' : 'mancante'}</span></td>
      <td>${escapeHtml(build.storage)}${build.sizeBytes ? ` - ${escapeHtml(formatBytes(build.sizeBytes))}` : ''}</td>
      <td><code>${escapeHtml(build.sha256 ? build.sha256.slice(0, 20) + '...' : '-')}</code></td>
      <td>${build.updatedAt ? escapeHtml(build.updatedAt) : '-'}</td>
      <td><input type="file" accept=".exe" data-build-file="${escapeHtml(build.platform)}"></td>
      <td><button class="button" data-build-upload="${escapeHtml(build.platform)}">Carica</button></td>
    </tr>
  `).join('');
  return adminShell({
    title: 'Admin',
    token,
    body: `<div class="eyebrow">Control room</div>
<h1>Sentinel Admin</h1>
<section class="grid3" style="margin-top:22px">
  <article class="card"><h3>Report sospetti</h3><p class="value">${suspiciousReports.length}</p></article>
  <article class="card"><h3>Ban report</h3><p class="value">${banReports.length}</p></article>
  <article class="card"><h3>Sessioni attive</h3><p class="value">${activeSessions}</p></article>
</section>
<section class="panel" style="margin-top:18px">
  <div class="eyebrow">Release download</div>
  <h2>Build Windows</h2>
  <p class="muted">Carica qui gli eseguibili che verranno serviti dalla pagina Download. Il filename pubblico resta pulito: Sentinel Anticheat.exe.</p>
  <table style="margin-top:16px">
    <thead><tr><th>Build</th><th>Stato</th><th>Storage</th><th>SHA256</th><th>Aggiornata</th><th>File</th><th>Azione</th></tr></thead>
    <tbody>${buildRows}</tbody>
  </table>
  <p class="muted" id="buildUploadStatus" style="margin-top:12px"></p>
</section>
<script>
  async function fileToBase64(file) {
    return await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(',')[1] || '');
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  document.querySelectorAll('[data-build-upload]').forEach(button => {
    button.addEventListener('click', async () => {
      const platform = button.dataset.buildUpload;
      const input = document.querySelector('[data-build-file="' + platform + '"]');
      const status = document.getElementById('buildUploadStatus');
      if (!input?.files?.length) {
        status.textContent = 'Seleziona prima un file .exe.';
        return;
      }
      const file = input.files[0];
      if (!file.name.toLowerCase().endsWith('.exe')) {
        status.textContent = 'Puoi caricare solo file .exe.';
        return;
      }
      button.disabled = true;
      status.textContent = 'Upload in corso...';
      try {
        const response = await fetch('/v1/admin/download/upload', {
          method:'POST',
          headers:{'content-type':'application/json'},
          body: JSON.stringify({
            token:${JSON.stringify(token)},
            platform,
            originalName:file.name,
            contentBase64: await fileToBase64(file)
          })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'upload_failed');
        status.textContent = 'Build caricata: ' + data.downloadName + ' (' + data.sizeBytes + ' bytes), SHA256 ' + data.sha256 + '.';
        setTimeout(() => location.reload(), 800);
      } catch (error) {
        status.textContent = 'Upload fallito: ' + error.message;
      } finally {
        button.disabled = false;
      }
    });
  });
</script>`
  });
}

function reportCard(report, token) {
  const payload = report.payload || {};
  const summary = payload.summary || {};
  const identity = payload.identity || {};
  const discord = identity.discord || {};
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  const searchText = [
    report.id,
    payload.reportId,
    report.discordId,
    discord.id,
    report.discordTag,
    discord.username,
    report.machineFingerprint,
    report.reviewStatus
  ].filter(Boolean).join(' ').toLowerCase();
  const topFindings = findings.slice(0, 6).map(finding => `
    <div class="finding">
      <strong>${escapeHtml(finding.severity)} ${escapeHtml(finding.type)}</strong>
      <span>${escapeHtml(finding.reason)}</span>
      <code>${escapeHtml(finding.path || finding.signal || '')}</code>
    </div>
  `).join('');

  const findingCount = summary.findingCount ?? findings.length;
  const highestSeverity = summary.highestSeverity || (findings[0]?.severity ?? 'unknown');

  return `<article class="panel" data-report-card data-search="${escapeHtml(searchText)}">
    <div style="display:flex; justify-content:space-between; gap:14px; align-items:flex-start">
      <div>
        <div class="eyebrow">Cybersecurity report</div>
        <h2>${escapeHtml(String(highestSeverity).toUpperCase())}</h2>
        <p>${escapeHtml(payload.generatedAt || report.receivedAt)}</p>
      </div>
      <div style="display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end">
        <div class="badge ${summary.suspicious ? 'danger' : ''}">${escapeHtml(findingCount)} findings</div>
        <div class="badge">${escapeHtml(report.reviewStatus || 'pending')}</div>
      </div>
    </div>
    <table style="margin:14px 0">
      <tbody>
        <tr><th>Report ID</th><td><code>${escapeHtml(payload.reportId || report.id)}</code></td></tr>
        <tr><th>Discord ID</th><td><code>${escapeHtml(discord.id || report.discordId || 'non collegato')}</code></td></tr>
        <tr><th>Discord user</th><td>${escapeHtml(discord.username || report.discordTag || 'unknown')}</td></tr>
        <tr><th>IP rete</th><td><code>${escapeHtml(identity.publicIp || report.publicIpSeen || 'unknown')}</code></td></tr>
        <tr><th>IP PC</th><td><code>${escapeHtml((identity.localIps || []).join(', ') || 'none')}</code></td></tr>
        <tr><th>Machine</th><td><code>${escapeHtml(String(identity.machineFingerprint || report.machineFingerprint || '').slice(0, 28))}</code></td></tr>
      </tbody>
    </table>
    ${topFindings || '<p class="muted">Nessun file sospetto in questo report.</p>'}
    <div class="actions">
      <a class="button primary" href="/admin/report/${encodeURIComponent(report.id)}.pdf?token=${encodeURIComponent(token)}">Scarica PDF</a>
      <button class="button" data-report-ban="${escapeHtml(report.id)}">Banna player</button>
      <button class="button" data-report-review="${escapeHtml(report.id)}" data-review-status="reviewed">Segna verificato</button>
      <button class="button" data-report-review="${escapeHtml(report.id)}" data-review-status="false_positive">Falso positivo</button>
    </div>
  </article>`;
}

function adminReportsHtml(token) {
  const reports = agentReports.filter(isReportSuspicious).slice(-100).reverse();
  const rows = reports.map(report => reportCard(report, token)).join('');
  return adminShell({
    title: 'Report',
    token,
    body: `<div class="eyebrow">User reports</div>
<h1>Report utenti segnalati</h1>
<input id="reportSearch" placeholder="Cerca per Discord ID, Report ID o Machine ID" style="margin-top:18px; max-width:520px">
<div id="reportList" style="display:grid; gap:14px; margin-top:12px">${rows || '<p class="muted">Nessun report sospetto disponibile.</p>'}</div>
<script>
  const reportSearch = document.getElementById('reportSearch');
  reportSearch?.addEventListener('input', () => {
    const query = reportSearch.value.trim().toLowerCase();
    document.querySelectorAll('[data-report-card]').forEach(card => {
      card.style.display = !query || card.dataset.search.includes(query) ? '' : 'none';
    });
  });
  document.querySelectorAll('[data-report-review]').forEach(button => {
    button.addEventListener('click', async () => {
      await fetch('/v1/admin/report/review', {
        method:'POST',
        headers:{'content-type':'application/json'},
        body: JSON.stringify({
          token:${JSON.stringify(token)},
          reportId: button.dataset.reportReview,
          status: button.dataset.reviewStatus
        })
      });
      location.reload();
    });
  });
  document.querySelectorAll('[data-report-ban]').forEach(button => {
    button.addEventListener('click', async () => {
      const reason = prompt('Motivo ban', 'manual_admin_review');
      if (!reason) return;
      await fetch('/v1/admin/ban', {
        method:'POST',
        headers:{'content-type':'application/json'},
        body: JSON.stringify({
          token:${JSON.stringify(token)},
          reportId: button.dataset.reportBan,
          reason
        })
      });
      location.href = '/admin/bans?token=' + encodeURIComponent(${JSON.stringify(token)});
    });
  });
</script>`
  });
}

function adminBansHtml(token) {
  const rows = banReports.slice(-100).reverse().map(ban => `
    <tr data-ban-row data-search="${escapeHtml([ban.id, ban.reportId, ban.discordId, ban.discordTag, ban.reason].filter(Boolean).join(' ').toLowerCase())}">
      <td><code>${escapeHtml(ban.discordId || 'unknown')}</code><br><span class="muted">${escapeHtml(ban.discordTag || '')}</span></td>
      <td><code>${escapeHtml(ban.id)}</code></td>
      <td>${escapeHtml(ban.reason)}</td>
      <td><code>${escapeHtml(ban.publicIp || 'unknown')}</code></td>
      <td>${escapeHtml(ban.createdAt)}</td>
      <td><span class="badge ${ban.active ? 'danger' : ''}">${ban.active ? 'attivo' : 'sbloccato'}</span></td>
      <td><button class="button" data-unban="${escapeHtml(ban.id)}">Sblocca</button></td>
    </tr>
  `).join('');

  return adminShell({
    title: 'Ban',
    token,
    body: `<div class="eyebrow">Enforcement</div>
<h1>Ban</h1>
<input id="banSearch" placeholder="Cerca per Discord ID, Ban ID o Report ID" style="margin-top:18px; max-width:520px">
<table style="margin-top:22px">
  <thead><tr><th>Discord</th><th>Ban ID</th><th>Motivo</th><th>IP rete</th><th>Data</th><th>Stato</th><th>Azione</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="7" class="muted">Nessun ban generato.</td></tr>'}</tbody>
</table>
<script>
  const banSearch = document.getElementById('banSearch');
  banSearch?.addEventListener('input', () => {
    const query = banSearch.value.trim().toLowerCase();
    document.querySelectorAll('[data-ban-row]').forEach(row => {
      row.style.display = !query || row.dataset.search.includes(query) ? '' : 'none';
    });
  });
  document.querySelectorAll('[data-unban]').forEach(button => {
    button.addEventListener('click', async () => {
      await fetch('/v1/admin/unban', {
        method:'POST',
        headers:{'content-type':'application/json'},
        body: JSON.stringify({ token:${JSON.stringify(token)}, banId: button.dataset.unban })
      });
      location.reload();
    });
  });
</script>`
  });
}

function discordStartHtml(state) {
  return layoutPage({
    title: 'Discord Link',
    body: `<main class="section">
  <div class="wrap admin-grid">
    <section>
      <div class="eyebrow">Discord authorization</div>
      <h1>Collega Discord</h1>
      <p class="hero-copy">Questa e' una simulazione locale dell'OAuth Discord. In produzione verra sostituita dal login ufficiale Discord.</p>
    </section>
    <form class="panel" action="/auth/discord/complete" method="get">
      <input type="hidden" name="state" value="${escapeHtml(state)}">
      <label>Discord ID</label>
      <input name="discordId" placeholder="123456789012345678" required>
      <label>Username Discord</label>
      <input name="username" placeholder="utente#0001">
      <button class="button primary" type="submit">Autorizza Sentinel</button>
    </form>
  </div>
</main>`
  });
}

function discordAuthorizationUrl(state) {
  const authUrl = new URL('https://discord.com/oauth2/authorize');
  authUrl.searchParams.set('client_id', discordClientId);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', discordRedirectUri);
  authUrl.searchParams.set('scope', 'identify');
  authUrl.searchParams.set('state', state);
  return authUrl.toString();
}

async function completeDiscordOAuth(code, state) {
  const tokenParams = new URLSearchParams();
  tokenParams.set('client_id', discordClientId);
  tokenParams.set('client_secret', discordClientSecret);
  tokenParams.set('grant_type', 'authorization_code');
  tokenParams.set('code', code);
  tokenParams.set('redirect_uri', discordRedirectUri);

  const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: tokenParams
  });
  if (!tokenResponse.ok) {
    throw new Error(`discord_token_failed_${tokenResponse.status}`);
  }

  const token = await tokenResponse.json();
  const userResponse = await fetch('https://discord.com/api/users/@me', {
    headers: { authorization: `Bearer ${token.access_token}` }
  });
  if (!userResponse.ok) {
    throw new Error(`discord_user_failed_${userResponse.status}`);
  }

  const user = await userResponse.json();
  const discordId = normalizeDiscordId(user.id);
  const username = user.global_name || user.username || discordId;
  discordLinks.set(state, {
    discordId,
    username,
    linkedAt: new Date().toISOString(),
    provider: 'discord_oauth2'
  });
  return { discordId, username };
}

function discordCompleteHtml(discordId) {
  return layoutPage({
    title: 'Discord Linked',
    body: `<main class="section"><div class="wrap"><h1>Discord collegato</h1><p class="hero-copy">ID collegato: <code>${escapeHtml(discordId)}</code>. Puoi tornare all'app Sentinel Anticheat.</p></div></main>`
  });
}

function dashboardHtml(token) {
  const rows = events.slice(-100).reverse().map(event => `
    <tr>
      <td>${escapeHtml(event.receivedAt)}</td>
      <td>${escapeHtml(event.serverId).slice(0, 14)}...</td>
      <td>${escapeHtml(event.playerFingerprint).slice(0, 14)}...</td>
      <td>${escapeHtml(event.detection)}</td>
      <td>${escapeHtml(event.severity)}</td>
      <td>${escapeHtml(event.localAction)}</td>
      <td>${escapeHtml(event.framework)}</td>
    </tr>
  `).join('');

  return adminShell({
    title: 'Detection dashboard',
    token,
    body: `<div class="eyebrow">Legacy telemetry</div>
<h1>Detection dashboard</h1>
<table style="margin-top:22px">
  <thead><tr><th>Time</th><th>Server</th><th>Player</th><th>Detection</th><th>Severity</th><th>Local action</th><th>Framework</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="7" class="muted">No events yet</td></tr>'}</tbody>
</table>`
  });
}

function authorize(req, payload) {
  const serverKey = req.headers['x-sentinel-key'];
  return serverKeys.has(String(serverKey || '')) && licenseKeys.has(String(payload.licenseKey || ''));
}

function isAdminToken(token) {
  return String(token || '') === dashboardToken;
}

function decide(event) {
  const severity = Number(event.severity || 0);
  let action = 'allow';

  if (severity >= 90) {
    action = 'ban';
  } else if (severity >= 75) {
    action = 'kick';
  } else if (severity >= 50) {
    action = 'warn';
  }

  const decision = {
    action,
    reason: event.detection || 'unknown',
    confidence: Math.min(99, Math.max(1, severity + 5)),
    nonce: randomUUID()
  };

  decision.signature = decisionSignature(decision);
  return decision;
}

function severityScore(value) {
  const text = String(value || '').toLowerCase();
  if (text === 'critical') return 95;
  if (text === 'high') return 86;
  if (text === 'medium') return 62;
  if (text === 'low') return 35;
  return 0;
}

function reportAction(report) {
  const summary = report.summary || {};
  if (!summary.suspicious) {
    return 'allow';
  }
  if (severityScore(summary.highestSeverity) >= 90) {
    return 'ban';
  }
  return 'review';
}

function isReportSuspicious(report) {
  return report?.payload?.summary?.suspicious === true;
}

function attachSessionIdentity(report, session) {
  report.identity = report.identity || {};
  report.identity.discord = report.identity.discord || {};
  if (session) {
    report.identity.discord.id = report.identity.discord.id || session.discordId;
    report.identity.discord.username = report.identity.discord.username || session.discordTag;
    report.identity.sessionId = session.sessionId;
  }
}

function addReportFromPayload({ decrypted, publicIp, payload, source = 'scan' }) {
  const session = payload.sessionId ? agentSessions.get(String(payload.sessionId)) : null;
  attachSessionIdentity(decrypted, session);

  const identity = decrypted.identity || {};
  const discord = identity.discord || {};
  const report = {
    id: decrypted.reportId || randomUUID(),
    receivedAt: new Date().toISOString(),
    source,
    publicIpSeen: publicIp,
    discordId: normalizeDiscordId(discord.id || payload.discordId || session?.discordId),
    discordTag: discord.username || payload.discordTag || session?.discordTag || '',
    machineFingerprint: payload.machineFingerprint || identity.machineFingerprint || '',
    reviewStatus: 'pending',
    reviewNote: '',
    payload: decrypted
  };

  agentReports.push(report);
  return report;
}

function addBanReport({ report, reason, publicIp }) {
  const existing = banReports.find(item => item.active && (
    (report.discordId && item.discordId === report.discordId) ||
    (report.machineFingerprint && item.machineFingerprint === report.machineFingerprint)
  ));
  if (existing) {
    existing.reason = reason || existing.reason;
    existing.updatedAt = new Date().toISOString();
    existing.reportId = report.id || existing.reportId;
    return existing;
  }

  const ban = {
    id: randomUUID(),
    reportId: report.id,
    discordId: report.discordId,
    discordTag: report.discordTag,
    publicIp: report.payload?.identity?.publicIp || publicIp || report.publicIpSeen,
    localIps: report.payload?.identity?.localIps || [],
    machineFingerprint: report.machineFingerprint,
    reason,
    reviewStatus: 'auto_banned',
    active: true,
    createdAt: new Date().toISOString(),
    report
  };
  banReports.push(ban);
  return ban;
}

function pdfEscape(value) {
  return String(value ?? '')
    .replaceAll('\\', '\\\\')
    .replaceAll('(', '\\(')
    .replaceAll(')', '\\)');
}

function wrapPdfText(text, width = 92) {
  const words = String(text ?? '').split(/\s+/);
  const lines = [];
  let line = '';
  for (const word of words) {
    if ((line + ' ' + word).trim().length > width) {
      if (line) lines.push(line);
      line = word;
    } else {
      line = (line + ' ' + word).trim();
    }
  }
  if (line) lines.push(line);
  return lines;
}

function buildReportPdf(report) {
  const payload = report.payload || {};
  const summary = payload.summary || {};
  const identity = payload.identity || {};
  const discord = identity.discord || {};
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  const reportId = payload.reportId || report.id;
  const logoPath = path.join(assetsDir, 'sentinel-logo.png');
  const fontPath = path.join(assetsDir, 'bahnschrift.ttf');
  const severity = String(summary.highestSeverity || (findings[0]?.severity ?? 'clean')).toUpperCase();
  const findingCount = summary.findingCount ?? findings.length;

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      autoFirstPage: false,
      size: 'A4',
      margin: 42,
      info: {
        Title: `Sentinel Anticheat Report ${reportId}`,
        Author: 'Sentinel Anticheat',
        Subject: 'FiveM anticheat review report'
      }
    });
    const chunks = [];
    doc.on('data', chunk => chunks.push(chunk));
    doc.on('error', reject);
    doc.on('end', () => resolve(Buffer.concat(chunks)));

    const fontRegular = fs.existsSync(fontPath) ? 'SentinelUI' : 'Helvetica';
    if (fs.existsSync(fontPath)) {
      doc.registerFont('SentinelUI', fontPath);
    }

    let pageNumber = 0;
    let pageWidth = 0;
    let pageHeight = 0;
    let left = 0;
    let right = 0;
    let contentWidth = 0;

    const startPage = () => {
      doc.addPage({ size: 'A4', margin: 42 });
      pageNumber += 1;
      pageWidth = doc.page.width;
      pageHeight = doc.page.height;
      left = doc.page.margins.left;
      right = pageWidth - doc.page.margins.right;
      contentWidth = right - left;

      doc.rect(0, 0, pageWidth, pageHeight).fill('#f4f7fb');
      doc.rect(0, 0, pageWidth, 92).fill('#07111b');
      doc.rect(0, 91, pageWidth, 1).fill('#0099ff');

      if (fs.existsSync(logoPath)) {
        doc.image(logoPath, left, 20, { width: 52, height: 52, fit: [52, 52] });
      }

      doc.fillColor('#edf5ff').font(fontRegular).fontSize(21).text('SENTINEL ANTICHEAT', left + 66, 24);
      doc.fillColor('#0099ff').font(fontRegular).fontSize(9).text('CYBERSECURITY REVIEW REPORT', left + 68, 54, {
        characterSpacing: 1.25
      });
      doc.fillColor('#9cafbf').font(fontRegular).fontSize(8)
        .text(`Pagina ${pageNumber}`, right - 84, 54, {
          width: 84,
          align: 'right'
        });
      doc.y = 120;
    };

    const ensureSpace = needed => {
      if (doc.y + needed <= pageHeight - 58) {
        return;
      }
      startPage();
    };

    const sectionTitle = title => {
      ensureSpace(34);
      doc.moveDown(0.6);
      doc.fillColor('#0099ff').font(fontRegular).fontSize(10).text(title.toUpperCase(), left, doc.y, {
        characterSpacing: 1.2
      });
      doc.moveDown(0.35);
    };

    const infoGrid = rows => {
      const rowHeight = 30;
      const labelWidth = 132;
      for (const [label, value] of rows) {
        ensureSpace(rowHeight + 4);
        const y = doc.y;
        doc.roundedRect(left, y, contentWidth, rowHeight, 6).fillAndStroke('#ffffff', '#d8e2ec');
        doc.fillColor('#617487').font(fontRegular).fontSize(8).text(String(label).toUpperCase(), left + 12, y + 9, {
          width: labelWidth
        });
        doc.fillColor('#07111b').font(fontRegular).fontSize(9.5).text(String(value || 'unknown'), left + labelWidth + 18, y + 8, {
          width: contentWidth - labelWidth - 30,
          lineBreak: false,
          ellipsis: true
        });
        doc.y = y + rowHeight + 6;
      }
    };

    startPage();

    doc.fillColor('#07111b').font(fontRegular).fontSize(26).text('Report di revisione anticheat', left, doc.y, {
      width: contentWidth - 130
    });
    doc.roundedRect(right - 110, 120, 110, 44, 8).fillAndStroke(summary.suspicious ? '#3b1019' : '#0d382b', summary.suspicious ? '#ff5d68' : '#52e0a4');
    doc.fillColor(summary.suspicious ? '#ffd2d6' : '#c7f7e1').font(fontRegular).fontSize(16).text(severity, right - 100, 133, {
      width: 90,
      align: 'center'
    });

    doc.moveDown(0.6);
    doc.fillColor('#40566c').font(fontRegular).fontSize(11).text(
      summary.suspicious
        ? 'Sentinel ha rilevato segnali che richiedono revisione manuale dello staff anticheat. Il report contiene indicatori tecnici, percorsi normalizzati e hash, non il contenuto dei file personali.'
        : 'La verifica non ha rilevato file o processi sospetti secondo le firme locali attive.',
      left,
      doc.y,
      { width: contentWidth }
    );

    sectionTitle('Identita e sessione');
    infoGrid([
      ['Report ID', reportId],
      ['Generato', payload.generatedAt || report.receivedAt],
      ['Discord ID', discord.id || report.discordId || 'non collegato'],
      ['Discord user', discord.username || report.discordTag || 'unknown'],
      ['IP rete', identity.publicIp || report.publicIpSeen || 'unknown'],
      ['IP PC', (identity.localIps || []).join(', ') || 'none'],
      ['Machine fingerprint', identity.machineFingerprint || report.machineFingerprint || 'unknown']
    ]);

    sectionTitle('Risultato analisi');
    infoGrid([
      ['Esito', summary.suspicious ? 'ATTENZIONE - elementi sospetti rilevati' : 'Pulito'],
      ['Severita', severity],
      ['Findings', findingCount],
      ['Modalita scan', payload.app?.scanMode || 'unknown'],
      ['Signature version', payload.app?.signatureVersion || 'unknown']
    ]);

    sectionTitle('File e segnali sospetti');
    if (!findings.length) {
      doc.roundedRect(left, doc.y, contentWidth, 42, 8).fillAndStroke('#ffffff', '#d8e2ec');
      doc.fillColor('#40566c').font(fontRegular).fontSize(11).text('Nessun elemento sospetto presente in questo report.', left + 14, doc.y + 14, {
        width: contentWidth - 28
      });
      doc.y += 52;
    } else {
      for (const [index, finding] of findings.slice(0, 80).entries()) {
        ensureSpace(104);
        const y = doc.y;
        doc.roundedRect(left, y, contentWidth, 94, 8).fillAndStroke('#ffffff', '#d8e2ec');
        doc.fillColor('#0099ff').font(fontRegular).fontSize(9).text(`#${index + 1}`, left + 12, y + 12, { width: 36 });
        doc.fillColor('#07111b').font(fontRegular).fontSize(12).text(`${finding.severity || 'unknown'} / ${finding.type || 'finding'}`, left + 52, y + 10, {
          width: contentWidth - 64
        });
        doc.fillColor('#40566c').font(fontRegular).fontSize(9.5).text(finding.reason || 'No reason provided', left + 52, y + 30, {
          width: contentWidth - 64
        });
        doc.fillColor('#075f9c').font(fontRegular).fontSize(8.6).text(`Path: ${finding.path || finding.signal || 'n/a'}`, left + 52, y + 50, {
          width: contentWidth - 64,
          ellipsis: true
        });
        doc.fillColor('#617487').font(fontRegular).fontSize(8.2).text(`SHA-256: ${finding.sha256 || 'n/a'}`, left + 52, y + 68, {
          width: contentWidth - 64,
          ellipsis: true
        });
        doc.y = y + 106;
      }
    }

    sectionTitle('Nota privacy');
    doc.fillColor('#40566c').font(fontRegular).fontSize(10).text(
      'Questo documento e pensato per revisione staff. Sentinel non allega contenuti personali dei file: vengono riportati solo metadati tecnici, indicatori, hash e riferimenti necessari alla verifica manuale.',
      left,
      doc.y,
      { width: contentWidth }
    );

    doc.end();
  });
}

async function saveDownloadBuild(payload) {
  const platform = String(payload.platform || '').toLowerCase();
  const build = baseDownloadBuilds().find(item => item.platform === platform);
  if (!build) {
    return { ok: false, status: 400, error: 'invalid_platform' };
  }

  const originalName = path.basename(String(payload.originalName || ''));
  if (originalName && !originalName.toLowerCase().endsWith('.exe')) {
    return { ok: false, status: 400, error: 'invalid_file_extension' };
  }

  const contentBase64 = String(payload.contentBase64 || '').replace(/^data:.*?;base64,/, '');
  let buffer;
  try {
    buffer = Buffer.from(contentBase64, 'base64');
  } catch {
    return { ok: false, status: 400, error: 'invalid_base64' };
  }

  if (buffer.length < 2 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
    return { ok: false, status: 400, error: 'invalid_windows_exe' };
  }

  if (buffer.length > 50 * 1024 * 1024) {
    return { ok: false, status: 413, error: 'file_too_large' };
  }

  const fileSha256 = sha256Hex(buffer);
  const uploadedAt = new Date().toISOString();

  if (cloudStorageEnabled) {
    await r2Client.send(new PutObjectCommand({
      Bucket: r2Bucket,
      Key: downloadObjectKey(build.filename),
      Body: buffer,
      ContentType: 'application/vnd.microsoft.portable-executable',
      ContentDisposition: `attachment; filename="${build.downloadName}"; filename*=UTF-8''${encodeURIComponent(build.downloadName)}`,
      CacheControl: 'no-store',
      Metadata: {
        platform: build.platform,
        originalName: originalName || build.downloadName,
        sha256: fileSha256,
        uploadedBy: 'sentinel-admin'
      }
    }));
  } else {
    fs.mkdirSync(downloadsDir, { recursive: true });
    const targetPath = path.join(downloadsDir, build.filename);
    const tempPath = `${targetPath}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tempPath, buffer);
    fs.renameSync(tempPath, targetPath);
  }

  const manifest = await readDownloadManifest();
  const nextManifest = {
    ...manifest,
    builds: {
      ...(manifest.builds || {}),
      [build.platform]: {
        platform: build.platform,
        label: build.label,
        filename: build.filename,
        downloadName: build.downloadName,
        route: build.route,
        storage: cloudStorageEnabled ? 'Cloudflare R2' : 'local',
        objectKey: downloadObjectKey(build.filename),
        publicUrl: cloudPublicUrl(build.filename) || null,
        sizeBytes: buffer.length,
        sha256: fileSha256,
        uploadedAt
      }
    }
  };
  await writeDownloadManifest(nextManifest);

  return {
    ok: true,
    platform: build.platform,
    filename: build.filename,
    downloadName: build.downloadName,
    storage: cloudStorageEnabled ? 'Cloudflare R2' : 'local',
    publicUrl: cloudPublicUrl(build.filename) || null,
    sha256: fileSha256,
    sizeBytes: buffer.length,
    updatedAt: uploadedAt
  };
}

async function streamDownload(res, filename, downloadName = filename) {
  const safeName = path.basename(filename);
  const safeDownloadName = path.basename(downloadName);
  if (cloudStorageEnabled) {
    const publicUrl = cloudPublicUrl(safeName);
    if (publicUrl) {
      res.writeHead(302, {
        location: publicUrl,
        'cache-control': 'no-store'
      });
      res.end();
      return;
    }

    try {
      const object = await r2Client.send(new GetObjectCommand({
        Bucket: r2Bucket,
        Key: downloadObjectKey(safeName)
      }));
      res.writeHead(200, {
        'content-type': object.ContentType || 'application/vnd.microsoft.portable-executable',
        'content-disposition': object.ContentDisposition || `attachment; filename="${safeDownloadName}"; filename*=UTF-8''${encodeURIComponent(safeDownloadName)}`,
        'cache-control': 'no-store',
        ...(object.ContentLength ? { 'content-length': String(object.ContentLength) } : {})
      });

      if (object.Body && typeof object.Body.pipe === 'function') {
        object.Body.pipe(res);
        return;
      }
      if (object.Body && typeof object.Body.transformToByteArray === 'function') {
        res.end(Buffer.from(await object.Body.transformToByteArray()));
        return;
      }
      res.end();
      return;
    } catch (error) {
      writeText(res, 404, `Download non trovato nello storage cloud: ${error.message}`);
      return;
    }
  }

  const filePath = path.join(downloadsDir, safeName);
  if (!fs.existsSync(filePath)) {
    writeText(res, 404, 'Download non ancora generato. Rigenera il pacchetto desktop.');
    return;
  }
  const ext = path.extname(safeName).toLowerCase();
  const contentType = ext === '.exe'
    ? 'application/vnd.microsoft.portable-executable'
    : 'application/zip';
  res.writeHead(200, {
    'content-type': contentType,
    'content-disposition': `attachment; filename="${safeDownloadName}"; filename*=UTF-8''${encodeURIComponent(safeDownloadName)}`,
    'cache-control': 'no-store'
  });
  fs.createReadStream(filePath).pipe(res);
}

function streamAsset(res, filename) {
  const safeName = path.basename(filename);
  const filePath = path.join(assetsDir, safeName);
  if (!fs.existsSync(filePath)) {
    writeText(res, 404, 'Asset not found');
    return;
  }
  const ext = path.extname(safeName).toLowerCase();
  const contentType = ext === '.png'
    ? 'image/png'
    : ext === '.ttf'
      ? 'font/ttf'
      : 'application/octet-stream';
  res.writeHead(200, {
    'content-type': contentType,
    'cache-control': 'no-store'
  });
  fs.createReadStream(filePath).pipe(res);
}

export const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${host}:${port}`);

  if (req.method === 'GET' && url.pathname === '/health') {
    writeJson(res, 200, {
      ok: true,
      events: events.length,
      reports: agentReports.length,
      bans: banReports.length,
      sessions: agentSessions.size
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/') {
    writeHtml(res, 200, homeHtml());
    return;
  }

  if (req.method === 'GET' && url.pathname.startsWith('/assets/')) {
    streamAsset(res, url.pathname.replace('/assets/', ''));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/download') {
    writeHtml(res, 200, await downloadHtml());
    return;
  }

  if (req.method === 'GET' && url.pathname === '/verify') {
    writeHtml(res, 200, await verifyHtml());
    return;
  }

  if (req.method === 'GET' && url.pathname === '/download/manifest.json') {
    writeJson(res, 200, await readDownloadManifest());
    return;
  }

  if (req.method === 'GET' && url.pathname === '/download/windows-x64') {
    await streamDownload(res, 'SentinelAnticheat-Windows-x64.exe', 'Sentinel Anticheat.exe');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/download/windows-x86') {
    await streamDownload(res, 'SentinelAnticheat-Windows-x86.exe', 'Sentinel Anticheat 32 bit.exe');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/admin') {
    writeHtml(res, 200, adminLoginHtml());
    return;
  }

  if (req.method === 'GET' && url.pathname === '/admin/panel') {
    if (!isAdminToken(url.searchParams.get('token'))) {
      writeHtml(res, 401, adminLoginHtml());
      return;
    }
    writeHtml(res, 200, await adminPanelHtml(url.searchParams.get('token')));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/admin/reports') {
    if (!isAdminToken(url.searchParams.get('token'))) {
      writeHtml(res, 401, adminLoginHtml());
      return;
    }
    writeHtml(res, 200, adminReportsHtml(url.searchParams.get('token')));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/admin/bans') {
    if (!isAdminToken(url.searchParams.get('token'))) {
      writeHtml(res, 401, adminLoginHtml());
      return;
    }
    writeHtml(res, 200, adminBansHtml(url.searchParams.get('token')));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/dashboard') {
    if (!isAdminToken(url.searchParams.get('token'))) {
      writeHtml(res, 401, adminLoginHtml());
      return;
    }
    writeHtml(res, 200, dashboardHtml(url.searchParams.get('token')));
    return;
  }

  if (req.method === 'GET' && url.pathname.startsWith('/admin/report/') && url.pathname.endsWith('.pdf')) {
    if (!isAdminToken(url.searchParams.get('token'))) {
      writeText(res, 401, 'Unauthorized');
      return;
    }
    const id = decodeURIComponent(url.pathname.replace('/admin/report/', '').replace(/\.pdf$/, ''));
    const report = agentReports.find(item => item.id === id);
    if (!report) {
      writeText(res, 404, 'Report not found');
      return;
    }
    const pdf = await buildReportPdf(report);
    res.writeHead(200, {
      'content-type': 'application/pdf',
      'content-disposition': `attachment; filename="sentinel-report-${id}.pdf"`,
      'cache-control': 'no-store'
    });
    res.end(pdf);
    return;
  }

  if (req.method === 'GET' && url.pathname === '/auth/discord/start') {
    const state = String(url.searchParams.get('state') || '');
    if (!state) {
      writeText(res, 400, 'Missing state');
      return;
    }
    oauthStates.set(state, { createdAt: Date.now() });
    if (discordOAuthConfigured) {
      res.writeHead(302, {
        location: discordAuthorizationUrl(state),
        'cache-control': 'no-store'
      });
      res.end();
      return;
    }
    writeHtml(res, 200, discordStartHtml(state));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/auth/discord/callback') {
    const state = String(url.searchParams.get('state') || '');
    const code = String(url.searchParams.get('code') || '');
    const pending = oauthStates.get(state);
    if (!discordOAuthConfigured) {
      writeText(res, 400, 'Discord OAuth non configurato. Usa DISCORD_CLIENT_ID e DISCORD_CLIENT_SECRET.');
      return;
    }
    if (!state || !code || !pending || Date.now() - pending.createdAt > 10 * 60 * 1000) {
      writeText(res, 400, 'Discord OAuth state non valido o scaduto.');
      return;
    }

    try {
      oauthStates.delete(state);
      const linked = await completeDiscordOAuth(code, state);
      writeHtml(res, 200, discordCompleteHtml(linked.discordId));
    } catch (error) {
      writeText(res, 502, `Discord OAuth non completato: ${error.message}`);
    }
    return;
  }

  if (req.method === 'GET' && url.pathname === '/auth/discord/complete') {
    const state = String(url.searchParams.get('state') || '');
    const discordId = normalizeDiscordId(url.searchParams.get('discordId'));
    const username = String(url.searchParams.get('username') || '');
    if (!state || !discordId) {
      writeText(res, 400, 'Missing state or Discord ID');
      return;
    }
    discordLinks.set(state, {
      discordId,
      username,
      linkedAt: new Date().toISOString()
    });
    writeHtml(res, 200, discordCompleteHtml(discordId));
    return;
  }

  if (req.method !== 'POST') {
    writeJson(res, 405, { error: 'method_not_allowed' });
    return;
  }

  let payload;
  try {
    payload = await readJson(req);
  } catch (error) {
    if (error.code === 'body_too_large') {
      writeJson(res, 413, { error: 'body_too_large', maxBodyBytes });
      return;
    }
    writeJson(res, 400, { error: 'invalid_json' });
    return;
  }

  const publicIp = publicIpFromRequest(req);

  if (url.pathname === '/v1/admin/login') {
    if (String(payload.username || '') === adminUser && String(payload.password || '') === adminPassword) {
      writeJson(res, 200, { ok: true, token: dashboardToken });
      return;
    }
    writeJson(res, 401, { error: 'invalid_credentials' });
    return;
  }

  if (url.pathname === '/v1/admin/reports/list') {
    if (!isAdminToken(payload.token)) {
      writeJson(res, 401, { error: 'unauthorized' });
      return;
    }
    writeJson(res, 200, { reports: agentReports.filter(isReportSuspicious).slice(-100) });
    return;
  }

  if (url.pathname === '/v1/admin/bans/list') {
    if (!isAdminToken(payload.token)) {
      writeJson(res, 401, { error: 'unauthorized' });
      return;
    }
    writeJson(res, 200, { bans: banReports.slice(-100) });
    return;
  }

  if (url.pathname === '/v1/admin/sessions/list') {
    if (!isAdminToken(payload.token)) {
      writeJson(res, 401, { error: 'unauthorized' });
      return;
    }
    const now = Date.now();
    writeJson(res, 200, {
      sessions: [...agentSessions.values()].map(session => ({
        sessionId: session.sessionId,
        discordId: session.discordId,
        discordTag: session.discordTag,
        machineFingerprint: session.machineFingerprint,
        status: session.status,
        createdAt: session.createdAt,
        lastHeartbeat: session.lastHeartbeat || null,
        ageSeconds: Math.floor((now - session.lastSeenAt) / 1000),
        active: session.status === 'active' && now - session.lastSeenAt <= sessionTtlMs
      }))
    });
    return;
  }

  if (url.pathname === '/v1/admin/unban') {
    if (!isAdminToken(payload.token)) {
      writeJson(res, 401, { error: 'unauthorized' });
      return;
    }
    const ban = banReports.find(item => item.id === payload.banId);
    if (ban) {
      ban.active = false;
      ban.unbannedAt = new Date().toISOString();
    }
    writeJson(res, 200, { ok: true });
    return;
  }

  if (url.pathname === '/v1/admin/download/upload') {
    if (!isAdminToken(payload.token)) {
      writeJson(res, 401, { error: 'unauthorized' });
      return;
    }
    const result = await saveDownloadBuild(payload);
    if (!result.ok) {
      writeJson(res, result.status || 400, { error: result.error || 'upload_failed' });
      return;
    }
    writeJson(res, 200, result);
    return;
  }

  if (url.pathname === '/v1/admin/report/review') {
    if (!isAdminToken(payload.token)) {
      writeJson(res, 401, { error: 'unauthorized' });
      return;
    }
    const report = agentReports.find(item => item.id === payload.reportId);
    if (!report) {
      writeJson(res, 404, { error: 'report_not_found' });
      return;
    }
    report.reviewStatus = String(payload.status || 'reviewed');
    report.reviewNote = String(payload.note || '');
    report.reviewedAt = new Date().toISOString();
    writeJson(res, 200, { ok: true, report });
    return;
  }

  if (url.pathname === '/v1/admin/ban') {
    if (!isAdminToken(payload.token)) {
      writeJson(res, 401, { error: 'unauthorized' });
      return;
    }
    const report = agentReports.find(item => item.id === payload.reportId);
    if (!report) {
      writeJson(res, 404, { error: 'report_not_found' });
      return;
    }
    report.reviewStatus = 'manual_ban';
    report.reviewNote = String(payload.reason || 'manual_admin_review');
    report.reviewedAt = new Date().toISOString();
    const ban = addBanReport({
      report,
      publicIp,
      reason: report.reviewNote
    });
    markSessionBlocked({
      sessionId: report.payload?.identity?.sessionId,
      discordId: report.discordId
    }, 'manual_admin_ban');
    writeJson(res, 200, { ok: true, ban });
    return;
  }

  if (!authorize(req, payload)) {
    writeJson(res, 401, { error: 'unauthorized' });
    return;
  }

  if (url.pathname === '/v1/license/verify') {
    writeJson(res, 200, {
      valid: true,
      plan: 'enterprise-dev',
      message: 'verified',
      serverId: payload.serverId
    });
    return;
  }

  if (url.pathname === '/v1/signatures/latest') {
    const feed = readSignatureFeed();
    writeJson(res, 200, {
      ok: true,
      version: feed.data.version || 'unknown',
      generatedAt: new Date().toISOString(),
      data: feed.data,
      dataRaw: feed.dataRaw,
      hmac: feed.hmac
    });
    return;
  }

  if (url.pathname === '/v1/agent/discord/status') {
    const link = discordLinks.get(String(payload.state || ''));
    writeJson(res, 200, {
      linked: Boolean(link),
      discordId: link?.discordId || null,
      username: link?.username || null
    });
    return;
  }

  if (url.pathname === '/v1/agent/precheck') {
    const ban = activeBanForIdentity({
      discordId: payload.discordId,
      machineFingerprint: payload.machineFingerprint,
      publicIp,
      localIps: payload.localIps
    });
    writeJson(res, 200, banDecisionPayload(ban));
    return;
  }

  if (url.pathname === '/v1/agent/connect') {
    const activeBan = activeBanForIdentity({
      discordId: payload.discordId,
      machineFingerprint: payload.machineFingerprint,
      publicIp
    });
    if (activeBan) {
      writeJson(res, 200, {
        accepted: false,
        ...banDecisionPayload(activeBan)
      });
      return;
    }

    const sessionId = randomUUID();
    const discordId = normalizeDiscordId(payload.discordId);
    const discordTag = String(payload.discordTag || '');
    const session = {
      sessionId,
      discordId,
      discordTag,
      machineFingerprint: String(payload.machineFingerprint || ''),
      appVersion: String(payload.appVersion || ''),
      publicIp,
      status: 'active',
      createdAt: new Date().toISOString(),
      lastSeenAt: Date.now()
    };
    agentSessions.set(sessionId, session);
    writeJson(res, 200, {
      accepted: true,
      sessionId,
      publicIp,
      sessionTtlSeconds: Math.floor(sessionTtlMs / 1000),
      serverTime: new Date().toISOString()
    });
    return;
  }

  if (url.pathname === '/v1/agent/heartbeat') {
    const session = agentSessions.get(String(payload.sessionId || ''));
    if (!session) {
      writeJson(res, 404, { active: false, reason: 'session_not_found' });
      return;
    }
    if (session.status === 'blocked') {
      writeJson(res, 200, {
        active: false,
        action: 'close',
        reason: session.blockReason || 'suspicious_scan_blocked'
      });
      return;
    }
    session.lastSeenAt = Date.now();
    session.status = payload.status === 'closing' ? 'closing' : 'active';
    session.lastHeartbeat = new Date().toISOString();
    writeJson(res, 200, {
      active: session.status === 'active',
      action: session.status === 'active' ? 'allow' : 'close'
    });
    return;
  }

  if (url.pathname === '/v1/agent/report') {
    let decrypted;
    try {
      decrypted = decryptEnvelope(payload.envelope);
    } catch (error) {
      writeJson(res, 400, { error: 'invalid_encrypted_report', detail: error.message });
      return;
    }

    const action = reportAction(decrypted);
    if (action === 'allow') {
      writeJson(res, 200, {
        accepted: true,
        stored: false,
        reportId: decrypted.reportId || null,
        action
      });
      return;
    }

    const report = addReportFromPayload({ decrypted, publicIp, payload, source: 'scan' });
    const ban = action === 'ban'
      ? addBanReport({
          report,
          publicIp,
          reason: decrypted.summary?.reason || decrypted.summary?.highestSeverity || 'suspicious scan'
        })
      : null;
    const blockedSession = markSessionBlocked(payload, action === 'ban' ? 'suspicious_scan_ban' : 'suspicious_scan_blocked');

    writeJson(res, 200, {
      accepted: true,
      stored: true,
      reportId: report.id,
      action,
      banId: ban?.id || null,
      sessionBlocked: Boolean(blockedSession)
    });
    return;
  }

  if (url.pathname === '/v1/agent/alert') {
    let decrypted;
    try {
      decrypted = decryptEnvelope(payload.envelope);
    } catch (error) {
      writeJson(res, 400, { error: 'invalid_encrypted_alert', detail: error.message });
      return;
    }

    const report = addReportFromPayload({ decrypted, publicIp, payload, source: 'runtime_alert' });
    const ban = addBanReport({
      report,
      publicIp,
      reason: decrypted.summary?.reason || decrypted.summary?.highestSeverity || 'runtime suspicious process'
    });
    markSessionBlocked(payload, 'runtime_suspicious_process');

    writeJson(res, 200, {
      accepted: true,
      action: 'ban',
      banId: ban.id,
      reportId: report.id
    });
    return;
  }

  if (url.pathname === '/v1/server/session/check') {
    const discordId = normalizeDiscordId(payload.discordId);
    const playerEndpoint = String(payload.playerEndpoint || '');
    const playerIp = playerEndpoint.split(':')[0] || '';
    const activeBan = activeBanForIdentity({
      discordId,
      publicIp: playerIp
    });
    if (activeBan) {
      writeJson(res, 200, {
        active: false,
        banned: true,
        banId: activeBan.id,
        discordId,
        reason: activeBan.reason || 'banned_by_sentinel'
      });
      return;
    }

    const session = activeSessionForDiscord(discordId);
    if (session) {
      writeJson(res, 200, {
        active: true,
        discordId,
        sessionId: session.sessionId,
        reason: 'active'
      });
      return;
    }

    const blockedSession = blockedSessionForDiscord(discordId);
    if (blockedSession) {
      writeJson(res, 200, {
        active: false,
        discordId,
        sessionId: blockedSession.sessionId,
        reason: blockedSession.blockReason || 'suspicious_scan_blocked'
      });
      return;
    }

    writeJson(res, 200, {
      active: false,
      discordId,
      sessionId: null,
      reason: 'desktop_anticheat_not_active'
    });
    return;
  }

  if (url.pathname === '/v1/detection/report') {
    const event = {
      serverId: payload.serverId,
      playerFingerprint: payload.playerFingerprint,
      detection: payload.detection,
      detailHash: payload.detailHash,
      severity: payload.severity,
      localAction: payload.localAction,
      framework: payload.framework,
      receivedAt: new Date().toISOString()
    };

    events.push(event);

    writeJson(res, 200, {
      accepted: true,
      eventId: fingerprint(`${event.serverId}:${event.playerFingerprint}:${event.receivedAt}`),
      decision: decide(event)
    });
    return;
  }

  if (url.pathname === '/v1/events/list') {
    writeJson(res, 200, {
      events: events.slice(-100)
    });
    return;
  }

  writeJson(res, 404, { error: 'not_found' });
});

server.listen(port, host, () => {
  console.log(`Sentinel Cloud mock listening on http://${host}:${port}`);
});
