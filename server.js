const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'apex-ib-secret-change-in-prod';

// ── DATABASE SETUP ────────────────────────────────────────────────────────────
let db;
try {
  const Database = require('better-sqlite3');
  const DB_PATH = process.env.DB_PATH || './apex_ib.db';
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );

    CREATE TABLE IF NOT EXISTS question_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      question_id TEXT NOT NULL,
      topic TEXT NOT NULL,
      status TEXT NOT NULL,
      score INTEGER,
      updated_at INTEGER DEFAULT (strftime('%s','now')),
      UNIQUE(user_id, question_id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      question_id TEXT NOT NULL,
      topic TEXT NOT NULL,
      score INTEGER NOT NULL,
      status TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s','now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS activity (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      questions_answered INTEGER DEFAULT 0,
      UNIQUE(user_id, date),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS user_state (
      user_id INTEGER PRIMARY KEY,
      last_topic TEXT DEFAULT 'All',
      last_question_index INTEGER DEFAULT 0,
      updated_at INTEGER DEFAULT (strftime('%s','now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);
  console.log('✓ Database ready');
} catch (err) {
  console.error('Database error:', err.message);
  db = null;
}

// ── AUTH HELPERS ──────────────────────────────────────────────────────────────
let bcrypt, jwt;
try {
  bcrypt = require('bcryptjs');
  jwt = require('jsonwebtoken');
} catch(e) {
  console.error('Missing auth deps:', e.message);
}

function verifyToken(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch(e) {
    return null;
  }
}

function jsonResponse(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch(e) { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ── SERVER ────────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS'
    });
    res.end();
    return;
  }

  const url = req.url.split('?')[0];

  // ── REGISTER ────────────────────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/auth/register') {
    if (!db || !bcrypt || !jwt) return jsonResponse(res, 500, { error: 'Server not ready' });
    const { email, password, name } = await readBody(req);
    if (!email || !password) return jsonResponse(res, 400, { error: 'Email and password required' });
    if (password.length < 6) return jsonResponse(res, 400, { error: 'Password must be at least 6 characters' });

    try {
      const hash = bcrypt.hashSync(password, 10);
      const stmt = db.prepare('INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)');
      const result = stmt.run(email.toLowerCase().trim(), hash, name || email.split('@')[0]);
      const token = jwt.sign({ userId: result.lastInsertRowid, email }, JWT_SECRET, { expiresIn: '90d' });
      return jsonResponse(res, 200, { token, name: name || email.split('@')[0] });
    } catch(e) {
      if (e.message.includes('UNIQUE')) return jsonResponse(res, 409, { error: 'Email already registered' });
      return jsonResponse(res, 500, { error: 'Registration failed' });
    }
  }

  // ── LOGIN ───────────────────────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/auth/login') {
    if (!db || !bcrypt || !jwt) return jsonResponse(res, 500, { error: 'Server not ready' });
    const { email, password } = await readBody(req);
    if (!email || !password) return jsonResponse(res, 400, { error: 'Email and password required' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return jsonResponse(res, 401, { error: 'Invalid email or password' });
    }
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '90d' });
    return jsonResponse(res, 200, { token, name: user.name });
  }

  // ── SAVE QUESTION RESULT ────────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/progress/save-result') {
    const user = verifyToken(req);
    if (!user) return jsonResponse(res, 401, { error: 'Unauthorized' });
    if (!db) return jsonResponse(res, 500, { error: 'DB not ready' });

    const { questionId, topic, status, score } = await readBody(req);
    if (!questionId || !status) return jsonResponse(res, 400, { error: 'Missing fields' });

    // Upsert question result
    db.prepare(`
      INSERT INTO question_results (user_id, question_id, topic, status, score, updated_at)
      VALUES (?, ?, ?, ?, ?, strftime('%s','now'))
      ON CONFLICT(user_id, question_id) DO UPDATE SET
        status = excluded.status,
        score = excluded.score,
        updated_at = strftime('%s','now')
    `).run(user.userId, questionId, topic, status, score || 0);

    // Log session history
    db.prepare(`
      INSERT INTO sessions (user_id, question_id, topic, score, status)
      VALUES (?, ?, ?, ?, ?)
    `).run(user.userId, questionId, topic, score || 0, status);

    // Update daily activity
    const today = new Date().toISOString().slice(0, 10);
    db.prepare(`
      INSERT INTO activity (user_id, date, questions_answered)
      VALUES (?, ?, 1)
      ON CONFLICT(user_id, date) DO UPDATE SET
        questions_answered = questions_answered + 1
    `).run(user.userId, today);

    return jsonResponse(res, 200, { ok: true });
  }

  // ── SAVE STATE (topic + position) ───────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/progress/save-state') {
    const user = verifyToken(req);
    if (!user) return jsonResponse(res, 401, { error: 'Unauthorized' });
    if (!db) return jsonResponse(res, 500, { error: 'DB not ready' });

    const { topic, questionIndex } = await readBody(req);
    db.prepare(`
      INSERT INTO user_state (user_id, last_topic, last_question_index, updated_at)
      VALUES (?, ?, ?, strftime('%s','now'))
      ON CONFLICT(user_id) DO UPDATE SET
        last_topic = excluded.last_topic,
        last_question_index = excluded.last_question_index,
        updated_at = strftime('%s','now')
    `).run(user.userId, topic || 'All', questionIndex || 0);

    return jsonResponse(res, 200, { ok: true });
  }

  // ── LOAD ALL PROGRESS ───────────────────────────────────────────────────────
  if (req.method === 'GET' && url === '/api/progress/load') {
    const user = verifyToken(req);
    if (!user) return jsonResponse(res, 401, { error: 'Unauthorized' });
    if (!db) return jsonResponse(res, 500, { error: 'DB not ready' });

    const results = db.prepare(
      'SELECT question_id, status, score FROM question_results WHERE user_id = ?'
    ).all(user.userId);

    const state = db.prepare(
      'SELECT last_topic, last_question_index FROM user_state WHERE user_id = ?'
    ).get(user.userId);

    // Session history: last 50
    const history = db.prepare(`
      SELECT topic, score, status, created_at
      FROM sessions WHERE user_id = ?
      ORDER BY created_at DESC LIMIT 50
    `).all(user.userId);

    // Activity: last 84 days (12 weeks)
    const activity = db.prepare(`
      SELECT date, questions_answered
      FROM activity WHERE user_id = ?
      ORDER BY date DESC LIMIT 84
    `).all(user.userId);

    // Streak calculation
    let streak = 0;
    const activityDates = new Set(activity.map(a => a.date));
    const today = new Date();
    for (let i = 0; i < 365; i++) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().slice(0, 10);
      if (activityDates.has(dateStr)) {
        streak++;
      } else if (i > 0) {
        break;
      }
    }

    return jsonResponse(res, 200, {
      results,
      state: state || { last_topic: 'All', last_question_index: 0 },
      history,
      activity,
      streak
    });
  }

  // ── STREAMING GRADE ─────────────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/grade') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const parsed = JSON.parse(body);
      parsed.stream = true;

      const options = {
        hostname: 'api.anthropic.com',
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.ANTHROPIC_API_KEY || '',
          'anthropic-version': '2023-06-01',
        }
      };

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Access-Control-Allow-Origin': '*',
        'Connection': 'keep-alive',
      });

      const apiReq = https.request(options, apiRes => {
        apiRes.on('data', chunk => res.write(chunk));
        apiRes.on('end', () => res.end());
      });

      apiReq.on('error', err => {
        res.write(`data: ${JSON.stringify({ type: 'error', message: err.message })}\n\n`);
        res.end();
      });

      apiReq.write(JSON.stringify(parsed));
      apiReq.end();
    });
    return;
  }

  // ── SERVE STATIC FILES ───────────────────────────────────────────────────────
  let filePath = '.' + req.url.split('?')[0];
  if (filePath === './') filePath = './dashboard.html';

  const ext = path.extname(filePath);
  const contentType = ext === '.html' ? 'text/html'
    : ext === '.js' ? 'application/javascript'
    : ext === '.css' ? 'text/css'
    : 'text/plain';

  fs.readFile(filePath, (err, content) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': contentType, 'Access-Control-Allow-Origin': '*' });
    res.end(content);
  });
});

server.listen(PORT, () => {
  console.log(`✓ Server running at http://localhost:${PORT}`);
  console.log(`✓ API key: ${process.env.ANTHROPIC_API_KEY ? 'SET ✓' : 'MISSING ✗'}`);
  console.log(`✓ DB: ${db ? 'READY ✓' : 'UNAVAILABLE ✗'}`);
});
