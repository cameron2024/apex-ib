const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'apex-ib-secret-change-in-prod';
const DB_PATH = process.env.DB_PATH || './db.json';

// ── PURE JS DATABASE (JSON file, no native deps) ──────────────
function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch(e) { console.error('DB load error:', e.message); }
  return { users: [], question_results: [], sessions: [], activity: [], user_state: [] };
}
function saveDB(db) {
  try { fs.writeFileSync(DB_PATH, JSON.stringify(db)); }
  catch(e) { console.error('DB save error:', e.message); }
}
let db = loadDB();
console.log('✓ DB loaded, users:', db.users.length);

// ── JWT (no dependency) ───────────────────────────────────────
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

// ── PASSWORD (SHA256+salt, no dependency) ─────────────────────
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
http.createServer(async (req, res) => {
  if (req.method==='OPTIONS') {
    res.writeHead(200,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*','Access-Control-Allow-Methods':'POST,GET,OPTIONS'});
    res.end(); return;
  }
  const url = req.url.split('?')[0];

  // PING
  if (url === '/api/ping') {
    return json(res, 200, { ok: true, users: db.users.length, ts: Date.now() });
  }

  // DEBUG — shows raw DB state (remove before production)
  if (url === '/api/debug') {
    db = loadDB();
    return json(res, 200, { users: db.users.map(u => ({id:u.id, email:u.email, name:u.name})), userCount: db.users.length });
  }

  // REGISTER
  if (req.method==='POST' && url==='/api/auth/register') {
    const {email,password,name} = await readBody(req);
    if (!email||!password) return json(res,400,{error:'Email and password required'});
    if (password.length<6) return json(res,400,{error:'Password must be at least 6 characters'});
    db = loadDB();
    const emailLower = email.toLowerCase().trim();
    if (db.users.find(u=>u.email===emailLower)) return json(res,409,{error:'Email already registered'});
    const id = Date.now();
    const displayName = name||emailLower.split('@')[0];
    db.users.push({id, email:emailLower, password_hash:hashPwd(password), name:displayName, created_at:nowSec()});
    saveDB(db);
    return json(res,200,{token:signToken({userId:id,email:emailLower}), name:displayName});
  }

  // LOGIN
  if (req.method==='POST' && url==='/api/auth/login') {
    const {email,password} = await readBody(req);
    if (!email||!password) return json(res,400,{error:'Email and password required'});
    db = loadDB();
    const user = db.users.find(u=>u.email===email.toLowerCase().trim());
    if (!user||!checkPwd(password,user.password_hash)) return json(res,401,{error:'Invalid email or password'});
    return json(res,200,{token:signToken({userId:user.id,email:user.email}), name:user.name});
  }

  // SAVE RESULT
  if (req.method==='POST' && url==='/api/progress/save-result') {
    const user = getUser(req); if (!user) return json(res,401,{error:'Unauthorized'});
    const {questionId,topic,status,score} = await readBody(req);
    db = loadDB();
    const ex = db.question_results.find(r=>r.user_id===user.userId&&r.question_id===questionId);
    if (ex) { ex.status=status; ex.score=score||0; ex.updated_at=nowSec(); }
    else db.question_results.push({user_id:user.userId,question_id:questionId,topic,status,score:score||0,updated_at:nowSec()});
    db.sessions.push({user_id:user.userId,question_id:questionId,topic,score:score||0,status,created_at:nowSec()});
    const t=today(); const act=db.activity.find(a=>a.user_id===user.userId&&a.date===t);
    if (act) act.questions_answered++; else db.activity.push({user_id:user.userId,date:t,questions_answered:1});
    saveDB(db);
    return json(res,200,{ok:true});
  }

  // SAVE STATE
  if (req.method==='POST' && url==='/api/progress/save-state') {
    const user = getUser(req); if (!user) return json(res,401,{error:'Unauthorized'});
    const {topic,questionIndex} = await readBody(req);
    db = loadDB();
    const ex = db.user_state.find(s=>s.user_id===user.userId);
    if (ex) { ex.last_topic=topic||'All'; ex.last_question_index=questionIndex||0; ex.updated_at=nowSec(); }
    else db.user_state.push({user_id:user.userId,last_topic:topic||'All',last_question_index:questionIndex||0,updated_at:nowSec()});
    saveDB(db);
    return json(res,200,{ok:true});
  }

  // LOAD PROGRESS
  if (req.method==='GET' && url==='/api/progress/load') {
    const user = getUser(req); if (!user) return json(res,401,{error:'Unauthorized'});
    db = loadDB();
    const results = db.question_results.filter(r=>r.user_id===user.userId).map(r=>({question_id:r.question_id,status:r.status,score:r.score}));
    const stateRow = db.user_state.find(s=>s.user_id===user.userId);
    const state = stateRow ? {last_topic:stateRow.last_topic,last_question_index:stateRow.last_question_index} : {last_topic:'All',last_question_index:0};
    const history = db.sessions.filter(s=>s.user_id===user.userId).sort((a,b)=>b.created_at-a.created_at).slice(0,50);
    const activity = db.activity.filter(a=>a.user_id===user.userId).sort((a,b)=>b.date.localeCompare(a.date)).slice(0,84);
    const actDates = new Set(activity.map(a=>a.date));
    let streak=0;
    for (let i=0;i<365;i++) { const d=new Date(); d.setDate(d.getDate()-i); const ds=d.toISOString().slice(0,10); if(actDates.has(ds))streak++; else if(i>0)break; }
    return json(res,200,{results,state,history,activity,streak});
  }

  // GRADE (streaming)
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

  // STATIC
  let filePath = '.'+req.url.split('?')[0];
  if (filePath==='./') filePath='./dashboard.html';
  const ext=path.extname(filePath);
  const ct=ext==='.html'?'text/html':ext==='.js'?'application/javascript':ext==='.css'?'text/css':'text/plain';
  fs.readFile(filePath,(err,content)=>{
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200,{'Content-Type':ct,'Access-Control-Allow-Origin':'*'});
    res.end(content);
  });

}).listen(PORT, () => {
  console.log(`✓ Server on port ${PORT}`);
  console.log(`✓ API key: ${process.env.ANTHROPIC_API_KEY?'SET':'MISSING'}`);
});
