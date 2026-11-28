// Netlify function: b2-upload
// Gives a signed-in school ADMIN a short-lived link to upload (or delete) one file in Backblaze B2.
// The B2 secret key stays here on the server; it is never sent to the browser.
//
// Environment variables (Netlify -> Site configuration -> Environment variables):
//   B2_KEY_ID      Backblaze application key ID (keyID)
//   B2_APP_KEY     Backblaze application key (shown once when created)
//   B2_BUCKET      GradeFlow
//   B2_ENDPOINT    s3.us-east-005.backblazeb2.com   (no https://)
//   B2_REGION      us-east-005
//   B2_PUBLIC_BASE https://f005.backblazeb2.com/file/GradeFlow
//   FIREBASE_API_KEY, FIREBASE_PROJECT_ID  (same values as in index.html)

const crypto = require('crypto');

const ALLOWED = {
  logo: { types: ['image/png', 'image/jpeg', 'image/webp', 'image/gif'], max: 2 * 1024 * 1024 },
  resource: {
    types: [
      'application/pdf', 'image/png', 'image/jpeg', 'image/webp',
      'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'text/plain'
    ],
    max: 25 * 1024 * 1024
  }
};
const EXT = {
  'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'image/gif': 'gif', 'application/pdf': 'pdf',
  'application/msword': 'doc', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
  'application/vnd.ms-powerpoint': 'ppt', 'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
  'application/vnd.ms-excel': 'xls', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
  'text/plain': 'txt'
};

const json = (status, body) => ({
  statusCode: status,
  headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' },
  body: JSON.stringify(body)
});

const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

// AWS Signature V4 presigned URL (query-string auth), host header only.
function presign(method, key, expires) {
  const { B2_KEY_ID, B2_APP_KEY, B2_BUCKET, B2_ENDPOINT, B2_REGION } = process.env;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const date = amzDate.slice(0, 8);
  const scope = `${date}/${B2_REGION}/s3/aws4_request`;
  const path = `/${B2_BUCKET}/${key.split('/').map(enc).join('/')}`;
  const q = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${B2_KEY_ID}/${scope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expires),
    'X-Amz-SignedHeaders': 'host'
  };
  const query = Object.keys(q).sort().map((k) => `${enc(k)}=${enc(q[k])}`).join('&');
  const canonical = [method, path, query, `host:${B2_ENDPOINT}\n`, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonical)].join('\n');
  const kDate = hmac('AWS4' + B2_APP_KEY, date);
  const kRegion = hmac(kDate, B2_REGION);
  const kService = hmac(kRegion, 's3');
  const kSigning = hmac(kService, 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(toSign).digest('hex');
  return `https://${B2_ENDPOINT}${path}?${query}&X-Amz-Signature=${signature}`;
}

// Confirms the Firebase ID token is real and returns the user's id.
async function verifyUser(idToken) {
  const r = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${process.env.FIREBASE_API_KEY}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken })
  });
  if (!r.ok) return null;
  const d = await r.json();
  return d.users && d.users[0] ? d.users[0].localId : null;
}

// Reads { role, centerId } from gradeflow_users/{uid} using the user's own token, so Firestore rules still apply.
async function getProfile(uid, idToken) {
  const url = `https://firestore.googleapis.com/v1/projects/${process.env.FIREBASE_PROJECT_ID}/databases/(default)/documents/gradeflow_users/${uid}`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${idToken}` } });
  if (!r.ok) return null;
  const f = (await r.json()).fields || {};
  const val = (x) => (x ? (x.stringValue ?? x.integerValue ?? '') : '');
  return { role: String(val(f.role)), centerId: String(val(f.centerId)) };
}

const safeName = (name) =>
  String(name || 'file').replace(/\.[^.]+$/, '').normalize('NFKD').replace(/[^\w\- ]+/g, '').trim().replace(/\s+/g, '-').slice(0, 60) || 'file';

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return json(204, {});
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed.' });

  const missing = ['B2_KEY_ID', 'B2_APP_KEY', 'B2_BUCKET', 'B2_ENDPOINT', 'B2_REGION', 'B2_PUBLIC_BASE', 'FIREBASE_API_KEY', 'FIREBASE_PROJECT_ID']
    .filter((k) => !process.env[k]);
  if (missing.length) return json(500, { error: 'Storage is not configured yet.' });

  const idToken = (event.headers.authorization || event.headers.Authorization || '').replace(/^Bearer\s+/i, '');
  if (!idToken) return json(401, { error: 'Please sign in first.' });

  let body;
  try { body = JSON.parse(event.body || '{}'); } catch (e) { return json(400, { error: 'Bad request.' }); }

  const uid = await verifyUser(idToken);
  if (!uid) return json(401, { error: 'Your session has expired. Sign in again.' });
  const profile = await getProfile(uid, idToken);
  if (!profile || profile.role !== 'admin' || !profile.centerId) return json(403, { error: 'Only the school admin can upload files.' });
  const center = profile.centerId.replace(/[^A-Za-z0-9_-]/g, '_');

  if (body.action === 'delete') {
    const key = String(body.key || '');
    if (!key.startsWith(`${center}/`) || key.includes('..')) return json(403, { error: 'You can only delete your own school files.' });
    return json(200, { deleteUrl: presign('DELETE', key, 300) });
  }

  const kind = ALLOWED[body.kind] ? body.kind : null;
  if (!kind) return json(400, { error: 'Unknown file type.' });
  const rule = ALLOWED[kind];
  const type = String(body.contentType || '');
  const size = Number(body.size || 0);
  if (!rule.types.includes(type)) return json(400, { error: 'That file type is not allowed.' });
  if (!size || size > rule.max) return json(400, { error: `File is too large (maximum ${Math.round(rule.max / 1048576)} MB).` });

  const stamp = Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
  const key = kind === 'logo'
    ? `${center}/logo/logo-${stamp}.${EXT[type]}`
    : `${center}/resources/${stamp}-${safeName(body.name)}.${EXT[type]}`;

  return json(200, {
    uploadUrl: presign('PUT', key, 600),
    key,
    publicUrl: `${process.env.B2_PUBLIC_BASE.replace(/\/$/, '')}/${key.split('/').map(encodeURIComponent).join('/')}`
  });
};
