require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { google } = require('googleapis');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const CHALLENGE_SECRET = process.env.CHALLENGE_SECRET || 'change-me-please-very-secret';
const MIN_FILL_SECONDS = parseInt(process.env.MIN_FILL_SECONDS || '4', 10); // bots submit instantly
const MAX_TOKEN_AGE_SECONDS = parseInt(process.env.MAX_TOKEN_AGE_SECONDS || '1800', 10); // 30 min
const SHEET_ID = process.env.GOOGLE_SHEET_ID;
const SHEET_TAB = process.env.GOOGLE_SHEET_TAB || 'Orders';
const DEDUPE_WINDOW_HOURS = parseInt(process.env.DEDUPE_WINDOW_HOURS || '24', 10);

const ALGERIA_PHONE_REGEX = /^0[5-7][0-9]{8}$/;

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1); // needed on Render so req.ip is the real client IP

// Anyone hammering /api/order or /api/challenge gets throttled per IP.
const challengeLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

const orderLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'too_many_requests' },
});

// ---------------------------------------------------------------------------
// Signed token helpers (stateless anti-bot: no DB/session needed)
// ---------------------------------------------------------------------------
function sign(payload) {
  return crypto.createHmac('sha256', CHALLENGE_SECRET).update(payload).digest('hex');
}

function makeToken(payload) {
  const b64 = Buffer.from(payload, 'utf8').toString('base64url');
  const sig = sign(payload);
  return `${b64}.${sig}`;
}

function readToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [b64, sig] = token.split('.');
  let payload;
  try {
    payload = Buffer.from(b64, 'base64url').toString('utf8');
  } catch {
    return null;
  }
  const expectedSig = sign(payload);
  // timing-safe compare
  const a = Buffer.from(sig || '');
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return payload;
}

// ---------------------------------------------------------------------------
// GET /api/challenge - issues a timing token + a tiny math captcha
// ---------------------------------------------------------------------------
app.get('/api/challenge', challengeLimiter, (req, res) => {
  const issuedAt = Date.now();
  const timeToken = makeToken(`ts:${issuedAt}`);

  const a = 1 + Math.floor(Math.random() * 8);
  const b = 1 + Math.floor(Math.random() * 8);
  const answer = a + b;
  const captchaToken = makeToken(`cap:${answer}:${issuedAt}`);

  res.json({
    timeToken,
    captchaToken,
    captchaQuestion: `${a} + ${b}`,
  });
});

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------
function validateTimeToken(timeToken) {
  const payload = readToken(timeToken);
  if (!payload || !payload.startsWith('ts:')) return { ok: false, reason: 'bad_time_token' };
  const issuedAt = parseInt(payload.slice(3), 10);
  if (!Number.isFinite(issuedAt)) return { ok: false, reason: 'bad_time_token' };
  const elapsedSec = (Date.now() - issuedAt) / 1000;
  if (elapsedSec < MIN_FILL_SECONDS) return { ok: false, reason: 'too_fast' };
  if (elapsedSec > MAX_TOKEN_AGE_SECONDS) return { ok: false, reason: 'expired' };
  return { ok: true };
}

function validateCaptcha(captchaToken, userAnswer) {
  const payload = readToken(captchaToken);
  if (!payload || !payload.startsWith('cap:')) return { ok: false, reason: 'bad_captcha_token' };
  const parts = payload.split(':');
  const correctAnswer = parseInt(parts[1], 10);
  const issuedAt = parseInt(parts[2], 10);
  if ((Date.now() - issuedAt) / 1000 > MAX_TOKEN_AGE_SECONDS) {
    return { ok: false, reason: 'expired' };
  }
  if (parseInt(userAnswer, 10) !== correctAnswer) {
    return { ok: false, reason: 'wrong_answer' };
  }
  return { ok: true };
}

function normalizePhone(raw) {
  if (!raw) return '';
  let p = String(raw).trim().replace(/[\s.-]/g, '');
  if (p.startsWith('+213')) p = '0' + p.slice(4);
  else if (p.startsWith('00213')) p = '0' + p.slice(5);
  else if (p.startsWith('213')) p = '0' + p.slice(3);
  return p;
}

// ---------------------------------------------------------------------------
// Google Sheets
// ---------------------------------------------------------------------------
let sheetsClientPromise = null;
function getSheetsClient() {
  if (!sheetsClientPromise) {
    const email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
    let key = process.env.GOOGLE_PRIVATE_KEY;
    if (!email || !key) {
      throw new Error('Google service account credentials are not configured');
    }
    key = key.replace(/\\n/g, '\n'); // Render env vars store \n literally
    const auth = new google.auth.JWT(email, null, key, [
      'https://www.googleapis.com/auth/spreadsheets',
    ]);
    sheetsClientPromise = auth.authorize().then(() => google.sheets({ version: 'v4', auth }));
  }
  return sheetsClientPromise;
}

async function findRecentDuplicate(sheets, phone, productName) {
  const range = `${SHEET_TAB}!A:K`;
  const result = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range });
  const rows = result.data.values || [];
  const cutoff = Date.now() - DEDUPE_WINDOW_HOURS * 60 * 60 * 1000;
  // Columns: A Timestamp(ISO) | B Name | C Phone | D Wilaya | E Address
  //          F Product | G Qty | H UnitPrice | I Total | J Status | K Flags
  for (let i = rows.length - 1; i >= 1; i--) {
    const row = rows[i];
    const ts = Date.parse(row[0]);
    if (!Number.isFinite(ts) || ts < cutoff) continue;
    if (row[2] === phone && row[5] === productName) return true;
  }
  return false;
}

async function appendOrder(sheets, order) {
  const range = `${SHEET_TAB}!A:K`;
  await sheets.spreadsheets.values.append({
    spreadsheetId: SHEET_ID,
    range,
    valueInputOption: 'USER_ENTERED',
    insertDataOption: 'INSERT_ROWS',
    requestBody: {
      values: [
        [
          new Date().toISOString(),
          order.name,
          order.phone,
          order.wilaya,
          order.address,
          order.product,
          order.qty,
          order.unitPrice,
          order.total,
          order.status,
          order.flags,
          order.ip,
          order.userAgent,
        ],
      ],
    },
  });
}

// ---------------------------------------------------------------------------
// POST /api/order
// ---------------------------------------------------------------------------
app.post('/api/order', orderLimiter, async (req, res) => {
  try {
    const body = req.body || {};

    // 1) Honeypot - real users never fill this hidden field
    if (body.website) {
      // Pretend success so the bot doesn't learn anything; we just drop it.
      return res.json({ ok: true });
    }

    // 2) Timing token - rejects instant/scripted submissions
    const timeCheck = validateTimeToken(body.timeToken);
    if (!timeCheck.ok) {
      return res.status(400).json({ ok: false, error: timeCheck.reason });
    }

    // 3) Math captcha
    const captchaCheck = validateCaptcha(body.captchaToken, body.captchaAnswer);
    if (!captchaCheck.ok) {
      return res.status(400).json({ ok: false, error: captchaCheck.reason });
    }

    // 4) Required fields
    const name = (body.name || '').trim();
    const wilaya = (body.wilaya || '').trim();
    const address = (body.address || '').trim();
    const product = (body.product || '').trim();
    const qty = Math.max(1, Math.min(10, parseInt(body.qty, 10) || 1));
    const unitPrice = parseInt(body.unitPrice, 10);
    const phone = normalizePhone(body.phone);

    if (!name || name.length < 3) {
      return res.status(400).json({ ok: false, error: 'invalid_name' });
    }
    if (!ALGERIA_PHONE_REGEX.test(phone)) {
      return res.status(400).json({ ok: false, error: 'invalid_phone' });
    }
    if (!wilaya) {
      return res.status(400).json({ ok: false, error: 'invalid_wilaya' });
    }
    if (!address || address.length < 5) {
      return res.status(400).json({ ok: false, error: 'invalid_address' });
    }
    if (!Number.isFinite(unitPrice) || unitPrice <= 0) {
      return res.status(400).json({ ok: false, error: 'invalid_price' });
    }

    const total = unitPrice * qty;
    const sheets = await getSheetsClient();
    const isDuplicate = await findRecentDuplicate(sheets, phone, product);

    await appendOrder(sheets, {
      name,
      phone,
      wilaya,
      address,
      product,
      qty,
      unitPrice,
      total,
      status: 'بانتظار التأكيد',
      flags: isDuplicate ? 'تكرار محتمل - تحقق قبل التأكيد' : '',
      ip: req.ip,
      userAgent: req.get('user-agent') || '',
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error('Order error:', err.message);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
