const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'apex-ib-secret-change-in-prod';

// ── POSTGRES ──────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGINT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT,
        created_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS question_results (
        user_id BIGINT,
        question_id TEXT,
        topic TEXT,
        status TEXT,
        score INT DEFAULT 0,
        updated_at BIGINT,
        PRIMARY KEY (user_id, question_id)
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        user_id BIGINT,
        question_id TEXT,
        topic TEXT,
        score INT DEFAULT 0,
        status TEXT,
        created_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS activity (
        user_id BIGINT,
        date TEXT,
        questions_answered INT DEFAULT 0,
        PRIMARY KEY (user_id, date)
      );
      CREATE TABLE IF NOT EXISTS user_state (
        user_id BIGINT PRIMARY KEY,
        last_topic TEXT DEFAULT 'All',
        last_question_index INT DEFAULT 0,
        updated_at BIGINT
      );
    `);
    console.log('✓ DB tables ready');
  } finally {
    client.release();
  }
}

// ── JWT ───────────────────────────────────────────────────────
function b64url(s) { return Buffer.from(s).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_'); }
function signToken(payload) {
  const h = b64url(JSON.stringify({alg:'HS256',typ:'JWT'}));
  const p = b64url(JSON.stringify({...payload, exp: Math.floor(Date.now()/1000)+60*60*24*90}));
  const s = crypto.createHmac('sha256',JWT_SECRET).update(h+'.'+p).digest('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
  return h+'.'+p+'.'+s;
}
function verifyToken(token) {
  try {
    const [h,p,s] = token.split('.');
    const expected = crypto.createHmac('sha256',JWT_SECRET).update(h+'.'+p).digest('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    if (s !== expected) return null;
    const payload = JSON.parse(Buffer.from(p,'base64').toString());
    return payload.exp > Math.floor(Date.now()/1000) ? payload : null;
  } catch(e) { return null; }
}
function getUser(req) {
  const auth = req.headers['authorization']||'';
  const t = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  return t ? verifyToken(t) : null;
}

// ── PASSWORD ──────────────────────────────────────────────────
function hashPwd(pwd) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt+':'+crypto.createHmac('sha256',salt).update(pwd).digest('hex');
}
function checkPwd(pwd, stored) {
  const [salt,hash] = stored.split(':');
  return crypto.createHmac('sha256',salt).update(pwd).digest('hex') === hash;
}

// ── HELPERS ───────────────────────────────────────────────────
function json(res, status, data) {
  res.writeHead(status, {'Content-Type':'application/json','Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*'});
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise(resolve => {
    let b=''; req.on('data',c=>b+=c); req.on('end',()=>{ try{resolve(JSON.parse(b))}catch(e){resolve({})} });
  });
}
const today = () => new Date().toISOString().slice(0,10);
const nowSec = () => Math.floor(Date.now()/1000);

// ── SERVER ────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  if (req.method==='OPTIONS') {
    res.writeHead(200,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*','Access-Control-Allow-Methods':'POST,GET,OPTIONS'});
    res.end(); return;
  }
  const url = req.url.split('?')[0];

  // PING
  if (url === '/api/ping') {
    const r = await pool.query('SELECT COUNT(*) FROM users');
    return json(res, 200, { ok: true, users: parseInt(r.rows[0].count), ts: Date.now() });
  }

  // REGISTER
  if (req.method==='POST' && url==='/api/auth/register') {
    try {
      const {email,password,name} = await readBody(req);
      if (!email||!password) return json(res,400,{error:'Email and password required'});
      if (password.length<6) return json(res,400,{error:'Password must be at least 6 characters'});
      const emailLower = email.toLowerCase().trim();
      const existing = await pool.query('SELECT id FROM users WHERE email=$1', [emailLower]);
      if (existing.rows.length > 0) return json(res,409,{error:'Email already registered'});
      const id = Date.now();
      const displayName = name || emailLower.split('@')[0];
      await pool.query(
        'INSERT INTO users (id,email,password_hash,name,created_at) VALUES ($1,$2,$3,$4,$5)',
        [id, emailLower, hashPwd(password), displayName, nowSec()]
      );
      return json(res,200,{token:signToken({userId:id,email:emailLower}), name:displayName});
    } catch(e) { return json(res,500,{error:e.message}); }
  }

  // LOGIN
  if (req.method==='POST' && url==='/api/auth/login') {
    try {
      const {email,password} = await readBody(req);
      if (!email||!password) return json(res,400,{error:'Email and password required'});
      const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
      const user = r.rows[0];
      if (!user || !checkPwd(password, user.password_hash)) return json(res,401,{error:'Invalid email or password'});
      return json(res,200,{token:signToken({userId:user.id,email:user.email}), name:user.name});
    } catch(e) { return json(res,500,{error:e.message}); }
  }

  // SAVE RESULT
  if (req.method==='POST' && url==='/api/progress/save-result') {
    const user = getUser(req); if (!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {questionId,topic,status,score} = await readBody(req);
      await pool.query(`
        INSERT INTO question_results (user_id,question_id,topic,status,score,updated_at)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (user_id,question_id) DO UPDATE
        SET status=$4, score=$5, updated_at=$6, topic=$3
      `, [user.userId, questionId, topic, status, score||0, nowSec()]);
      await pool.query(
        'INSERT INTO sessions (user_id,question_id,topic,score,status,created_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [user.userId, questionId, topic, score||0, status, nowSec()]
      );
      await pool.query(`
        INSERT INTO activity (user_id,date,questions_answered)
        VALUES ($1,$2,1)
        ON CONFLICT (user_id,date) DO UPDATE
        SET questions_answered = activity.questions_answered + 1
      `, [user.userId, today()]);
      return json(res,200,{ok:true});
    } catch(e) { return json(res,500,{error:e.message}); }
  }

  // SAVE STATE
  if (req.method==='POST' && url==='/api/progress/save-state') {
    const user = getUser(req); if (!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {topic,questionIndex} = await readBody(req);
      await pool.query(`
        INSERT INTO user_state (user_id,last_topic,last_question_index,updated_at)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (user_id) DO UPDATE
        SET last_topic=$2, last_question_index=$3, updated_at=$4
      `, [user.userId, topic||'All', questionIndex||0, nowSec()]);
      return json(res,200,{ok:true});
    } catch(e) { return json(res,500,{error:e.message}); }
  }

  // LOAD PROGRESS
  if (req.method==='GET' && url==='/api/progress/load') {
    const user = getUser(req); if (!user) return json(res,401,{error:'Unauthorized'});
    try {
      const [resultsR, stateR, historyR, activityR] = await Promise.all([
        pool.query('SELECT question_id,topic,status,score FROM question_results WHERE user_id=$1', [user.userId]),
        pool.query('SELECT last_topic,last_question_index FROM user_state WHERE user_id=$1', [user.userId]),
        pool.query('SELECT question_id,topic,score,status,created_at FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50', [user.userId]),
        pool.query('SELECT date,questions_answered FROM activity WHERE user_id=$1 ORDER BY date DESC LIMIT 84', [user.userId])
      ]);
      const state = stateR.rows[0] || {last_topic:'All', last_question_index:0};
      const actDates = new Set(activityR.rows.map(a=>a.date));
      let streak=0;
      for (let i=0;i<365;i++) {
        const d=new Date(); d.setDate(d.getDate()-i);
        const ds=d.toISOString().slice(0,10);
        if (actDates.has(ds)) streak++; else if (i>0) break;
      }
      return json(res,200,{
        results: resultsR.rows,
        state,
        history: historyR.rows,
        activity: activityR.rows,
        streak
      });
    } catch(e) { return json(res,500,{error:e.message}); }
  }

  // GRADE (streaming proxy to Anthropic)
  if (req.method==='POST' && url==='/api/grade') {
    let body=''; req.on('data',c=>body+=c); req.on('end',()=>{
      const parsed=JSON.parse(body); parsed.stream=true;
      res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Access-Control-Allow-Origin':'*','Connection':'keep-alive'});
      const apiReq=https.request({hostname:'api.anthropic.com',path:'/v1/messages',method:'POST',headers:{'Content-Type':'application/json','x-api-key':process.env.ANTHROPIC_API_KEY||'','anthropic-version':'2023-06-01'}},apiRes=>{
        apiRes.on('data',c=>res.write(c)); apiRes.on('end',()=>res.end());
      });
      apiReq.on('error',err=>{res.write(`data: ${JSON.stringify({type:'error',message:err.message})}\n\n`);res.end();});
      apiReq.write(JSON.stringify(parsed)); apiReq.end();
    }); return;
  }

  // QUESTIONS JSON — explicit route to avoid static-file resolution issues
  if (url === '/questions.json') {
    const qPath = path.join(__dirname, 'questions.json');
    return fs.readFile(qPath, (err, content) => {
      if (err) { res.writeHead(404,{'Content-Type':'text/plain'}); res.end('questions.json not found at: '+qPath); return; }
      res.writeHead(200, {'Content-Type':'application/json','Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age=3600'});
      res.end(content);
    });
  }

  // DEBUG — list files (remove after confirming deploy works)
  if (url === '/api/debug-files') {
    const dir = __dirname;
    const files = fs.readdirSync(dir);
    return json(res, 200, { dir, files });
  }

  // STATIC FILES
  let filePath = path.join(__dirname, req.url.split('?')[0]);
  if (req.url.split('?')[0]==='/') filePath=path.join(__dirname,'dashboard.html');
  const ext=path.extname(filePath);
  const ct=ext==='.html'?'text/html':ext==='.js'?'application/javascript':ext==='.css'?'text/css':ext==='.json'?'application/json':'text/plain';
  fs.readFile(filePath,(err,content)=>{
    if (err) { res.writeHead(404,{'Content-Type':'text/plain'}); res.end('Not found: '+req.url); return; }
    res.writeHead(200,{'Content-Type':ct,'Access-Control-Allow-Origin':'*'});
    res.end(content);
  });
});

// ── BOOT ──────────────────────────────────────────────────────
initDB().then(() => {
  server.listen(PORT, () => {
    console.log(`✓ Server on port ${PORT}`);
    console.log(`✓ API key: ${process.env.ANTHROPIC_API_KEY ? 'SET' : 'MISSING'}`);
    console.log(`✓ Database: ${process.env.DATABASE_URL ? 'Postgres connected' : 'NO DATABASE_URL — set this in Railway'}`);
  });
}).catch(err => {
  console.error('✗ DB init failed:', err.message);
  process.exit(1);
});
