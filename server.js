const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;

// Load questions.json into memory at startup
let QUESTIONS_DATA = null;
try {
  QUESTIONS_DATA = fs.readFileSync(path.join(__dirname, 'questions.json'), 'utf8');
  console.log('questions.json loaded: ' + JSON.parse(QUESTIONS_DATA).length + ' questions');
} catch(e) {
  console.error('WARNING: questions.json not found or invalid:', e.message);
}
const JWT_SECRET = process.env.JWT_SECRET || 'apex-ib-secret-change-in-prod';
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_MONTHLY_PRICE_ID = process.env.STRIPE_MONTHLY_PRICE_ID || '';
const STRIPE_PASS_PRICE_ID = process.env.STRIPE_PASS_PRICE_ID || '';
const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const FREE_DAILY_LIMIT = 5;

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
        plan TEXT DEFAULT 'free',
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        created_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS question_results (
        user_id BIGINT, question_id TEXT, topic TEXT,
        status TEXT, score INT DEFAULT 0, updated_at BIGINT,
        PRIMARY KEY (user_id, question_id)
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY, user_id BIGINT,
        question_id TEXT, topic TEXT,
        score INT DEFAULT 0, status TEXT, created_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS activity (
        user_id BIGINT, date TEXT, questions_answered INT DEFAULT 0,
        PRIMARY KEY (user_id, date)
      );
      CREATE TABLE IF NOT EXISTS user_state (
        user_id BIGINT PRIMARY KEY, last_topic TEXT DEFAULT 'All',
        last_question_index INT DEFAULT 0, updated_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS stripe_events (
        id TEXT PRIMARY KEY, processed_at BIGINT
      );
    `);
    await client.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'free';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT;
    `);
    console.log('DB ready');
  } finally { client.release(); }
}

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
function hashPwd(pwd) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt+':'+crypto.createHmac('sha256',salt).update(pwd).digest('hex');
}
function checkPwd(pwd, stored) {
  const [salt,hash] = stored.split(':');
  return crypto.createHmac('sha256',salt).update(pwd).digest('hex') === hash;
}
function json(res, status, data) {
  res.writeHead(status, {'Content-Type':'application/json','Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*'});
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise(resolve => {
    let b=''; req.on('data',c=>b+=c); req.on('end',()=>{ try{resolve(JSON.parse(b))}catch(e){resolve({})} });
  });
}
function readRawBody(req) {
  return new Promise(resolve => {
    const chunks=[]; req.on('data',c=>chunks.push(c)); req.on('end',()=>resolve(Buffer.concat(chunks)));
  });
}
const today = () => new Date().toISOString().slice(0,10);
const nowSec = () => Math.floor(Date.now()/1000);

function stripeRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? new URLSearchParams(body).toString() : '';
    const req = https.request({
      hostname:'api.stripe.com', path, method,
      headers:{
        'Authorization':'Bearer '+STRIPE_SECRET_KEY,
        'Content-Type':'application/x-www-form-urlencoded',
        'Content-Length':Buffer.byteLength(data)
      }
    }, res => {
      let raw=''; res.on('data',c=>raw+=c);
      res.on('end',()=>{ try{resolve(JSON.parse(raw))}catch(e){reject(e)} });
    });
    req.on('error',reject);
    if (data) req.write(data);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method==='OPTIONS') {
    res.writeHead(200,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*','Access-Control-Allow-Methods':'POST,GET,OPTIONS'});
    res.end(); return;
  }
  const url = req.url.split('?')[0];

  if (url==='/api/ping') {
    const r = await pool.query('SELECT COUNT(*) FROM users');
    return json(res,200,{ok:true,users:parseInt(r.rows[0].count),ts:Date.now()});
  }

  if (req.method==='POST' && url==='/api/auth/register') {
    try {
      const {email,password,name} = await readBody(req);
      if (!email||!password) return json(res,400,{error:'Email and password required'});
      if (password.length<6) return json(res,400,{error:'Password must be at least 6 characters'});
      const emailLower = email.toLowerCase().trim();
      const existing = await pool.query('SELECT id FROM users WHERE email=$1',[emailLower]);
      if (existing.rows.length>0) return json(res,409,{error:'Email already registered'});
      const id = Date.now();
      const displayName = name||emailLower.split('@')[0];
      await pool.query('INSERT INTO users (id,email,password_hash,name,plan,created_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [id,emailLower,hashPwd(password),displayName,'free',nowSec()]);
      return json(res,200,{token:signToken({userId:id,email:emailLower}),name:displayName,plan:'free'});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/auth/login') {
    try {
      const {email,password} = await readBody(req);
      if (!email||!password) return json(res,400,{error:'Email and password required'});
      const r = await pool.query('SELECT * FROM users WHERE email=$1',[email.toLowerCase().trim()]);
      const user = r.rows[0];
      if (!user||!checkPwd(password,user.password_hash)) return json(res,401,{error:'Invalid email or password'});
      return json(res,200,{token:signToken({userId:user.id,email:user.email}),name:user.name,plan:user.plan||'free'});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/progress/save-result') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {questionId,topic,status,score} = await readBody(req);
      await pool.query(`INSERT INTO question_results (user_id,question_id,topic,status,score,updated_at) VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (user_id,question_id) DO UPDATE SET status=$4,score=$5,updated_at=$6,topic=$3`,
        [user.userId,questionId,topic,status,score||0,nowSec()]);
      await pool.query('INSERT INTO sessions (user_id,question_id,topic,score,status,created_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [user.userId,questionId,topic,score||0,status,nowSec()]);
      await pool.query(`INSERT INTO activity (user_id,date,questions_answered) VALUES ($1,$2,1)
        ON CONFLICT (user_id,date) DO UPDATE SET questions_answered=activity.questions_answered+1`,
        [user.userId,today()]);
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/progress/save-state') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {topic,questionIndex} = await readBody(req);
      await pool.query(`INSERT INTO user_state (user_id,last_topic,last_question_index,updated_at) VALUES ($1,$2,$3,$4)
        ON CONFLICT (user_id) DO UPDATE SET last_topic=$2,last_question_index=$3,updated_at=$4`,
        [user.userId,topic||'All',questionIndex||0,nowSec()]);
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='GET' && url==='/api/progress/load') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const [resultsR,stateR,historyR,activityR,userR] = await Promise.all([
        pool.query('SELECT question_id,topic,status,score FROM question_results WHERE user_id=$1',[user.userId]),
        pool.query('SELECT last_topic,last_question_index FROM user_state WHERE user_id=$1',[user.userId]),
        pool.query('SELECT question_id,topic,score,status,created_at FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',[user.userId]),
        pool.query('SELECT date,questions_answered FROM activity WHERE user_id=$1 ORDER BY date DESC LIMIT 84',[user.userId]),
        pool.query('SELECT plan, created_at FROM users WHERE id=$1',[user.userId])
      ]);
      const state = stateR.rows[0]||{last_topic:'All',last_question_index:0};
      const actDates = new Set(activityR.rows.map(a=>a.date));
      let streak=0;
      for(let i=0;i<365;i++){
        const d=new Date(); d.setDate(d.getDate()-i);
        const ds=d.toISOString().slice(0,10);
        if(actDates.has(ds)) streak++; else if(i>0) break;
      }
      const todayAct = activityR.rows.find(a=>a.date===today());
      const gradedToday = todayAct ? parseInt(todayAct.questions_answered) : 0;
      const plan = userR.rows[0]?.plan||'free';
      const memberSince = userR.rows[0]?.created_at || null;
      return json(res,200,{results:resultsR.rows,state,history:historyR.rows,activity:activityR.rows,streak,plan,gradedToday,memberSince});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GRADE — free tier cap enforced server-side; guests allowed with header-based session cap
  if (req.method==='POST' && url==='/api/grade') {
    const user=getUser(req);

    // Guest (no token): allow but pass through — cap tracked client-side via localStorage
    // Authenticated: enforce server-side plan cap
    if (user) {
      try {
        const userR = await pool.query('SELECT plan FROM users WHERE id=$1',[user.userId]);
        const plan = userR.rows[0]?.plan||'free';
        if(plan==='free'){
          const actR = await pool.query('SELECT questions_answered FROM activity WHERE user_id=$1 AND date=$2',[user.userId,today()]);
          const count = actR.rows[0] ? parseInt(actR.rows[0].questions_answered) : 0;
          if(count>=FREE_DAILY_LIMIT){
            return json(res,402,{error:'limit_reached',message:`You've used all ${FREE_DAILY_LIMIT} free grades today. Upgrade to keep going.`,plan:'free',gradedToday:count});
          }
        }
      } catch(e){return json(res,500,{error:e.message});}
    }

    let body=''; req.on('data',c=>body+=c); req.on('end',()=>{
      const parsed=JSON.parse(body); parsed.stream=true;
      res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Access-Control-Allow-Origin':'*','Connection':'keep-alive'});
      const apiReq=https.request({hostname:'api.anthropic.com',path:'/v1/messages',method:'POST',
        headers:{'Content-Type':'application/json','x-api-key':process.env.ANTHROPIC_API_KEY||'','anthropic-version':'2023-06-01'}},
        apiRes=>{ apiRes.on('data',c=>res.write(c)); apiRes.on('end',()=>res.end()); });
      apiReq.on('error',err=>{res.write(`data: ${JSON.stringify({type:'error',message:err.message})}\n\n`);res.end();});
      apiReq.write(JSON.stringify(parsed)); apiReq.end();
    }); return;
  }

  // STRIPE: CREATE CHECKOUT SESSION
  if (req.method==='POST' && url==='/api/stripe/checkout') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    if(!STRIPE_SECRET_KEY) return json(res,503,{error:'Stripe not configured'});
    try {
      const {plan} = await readBody(req);
      const priceId = plan==='pass' ? STRIPE_PASS_PRICE_ID : STRIPE_MONTHLY_PRICE_ID;
      if(!priceId) return json(res,400,{error:'Invalid plan or price not configured'});
      const userR = await pool.query('SELECT email,stripe_customer_id FROM users WHERE id=$1',[user.userId]);
      const dbUser = userR.rows[0];
      const params = {
        'payment_method_types[0]':'card',
        'line_items[0][price]':priceId,
        'line_items[0][quantity]':'1',
        'mode': plan==='pass' ? 'payment' : 'subscription',
        'success_url':`${APP_URL}/dashboard.html?upgraded=1`,
        'cancel_url':`${APP_URL}/pricing.html`,
        'metadata[user_id]':String(user.userId),
        'metadata[plan]':plan
      };
      if(dbUser.stripe_customer_id) params['customer']=dbUser.stripe_customer_id;
      else params['customer_email']=dbUser.email;
      const session = await stripeRequest('POST','/v1/checkout/sessions',params);
      if(session.error) return json(res,400,{error:session.error.message});
      return json(res,200,{url:session.url});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // STRIPE: WEBHOOK
  if (req.method==='POST' && url==='/api/stripe/webhook') {
    if(!STRIPE_WEBHOOK_SECRET) return json(res,503,{error:'Webhook not configured'});
    try {
      const rawBody = await readRawBody(req);
      const sig = req.headers['stripe-signature']||'';
      const parts = sig.split(',').reduce((acc,p)=>{const [k,v]=p.split('=');acc[k]=v;return acc;},{});
      const expected = crypto.createHmac('sha256',STRIPE_WEBHOOK_SECRET).update(parts.t+'.'+rawBody.toString()).digest('hex');
      if(expected!==parts.v1) return json(res,400,{error:'Invalid signature'});
      const event = JSON.parse(rawBody.toString());
      const already = await pool.query('SELECT id FROM stripe_events WHERE id=$1',[event.id]);
      if(already.rows.length>0) return json(res,200,{ok:true,skipped:true});
      await pool.query('INSERT INTO stripe_events (id,processed_at) VALUES ($1,$2)',[event.id,nowSec()]);
      const obj = event.data.object;
      if(event.type==='checkout.session.completed'){
        const userId=obj.metadata?.user_id, plan=obj.metadata?.plan;
        if(userId&&plan){
          await pool.query('UPDATE users SET plan=$1,stripe_customer_id=$2,stripe_subscription_id=$3 WHERE id=$4',
            [plan,obj.customer||null,obj.subscription||null,userId]);
          console.log(`Upgraded user ${userId} to ${plan}`);
        }
      }
      if(event.type==='customer.subscription.deleted'){
        await pool.query('UPDATE users SET plan=$1,stripe_subscription_id=NULL WHERE stripe_subscription_id=$2',['free',obj.id]);
        console.log(`Subscription ${obj.id} cancelled — downgraded to free`);
      }
      return json(res,200,{ok:true});
    } catch(e){console.error('Webhook error:',e.message);return json(res,400,{error:e.message});}
  }

  // ADMIN: SET PLAN
  if (req.method==='POST' && url==='/api/admin/set-plan') {
    const adminKey=req.headers['x-admin-secret']||'';
    if(!ADMIN_SECRET||adminKey!==ADMIN_SECRET) return json(res,401,{error:'Unauthorized'});
    try {
      const {email,plan} = await readBody(req);
      if(!email||!plan) return json(res,400,{error:'email and plan required'});
      if(!['free','monthly','pass'].includes(plan)) return json(res,400,{error:'plan must be free, monthly, or pass'});
      const r = await pool.query('UPDATE users SET plan=$1 WHERE email=$2 RETURNING id,email,plan',[plan,email.toLowerCase().trim()]);
      if(r.rows.length===0) return json(res,404,{error:'User not found'});
      console.log(`Admin override: ${email} → ${plan}`);
      return json(res,200,{ok:true,user:r.rows[0]});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (url==='/api/questions') {
    if (!QUESTIONS_DATA) return json(res, 503, { error: 'questions.json not loaded — ensure the file is committed to your repository' });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=3600' });
    res.end(QUESTIONS_DATA);
    return;
  }

  if (url==='/api/debug-files') {
    return json(res,200,{dir:__dirname,files:fs.readdirSync(__dirname)});
  }

  let filePath=path.join(__dirname,req.url.split('?')[0]);
  if(req.url.split('?')[0]==='/') filePath=path.join(__dirname,'dashboard.html');
  const ext=path.extname(filePath);
  const ct=ext==='.html'?'text/html':ext==='.js'?'application/javascript':ext==='.css'?'text/css':ext==='.json'?'application/json':'text/plain';
  fs.readFile(filePath,(err,content)=>{
    if(err){res.writeHead(404,{'Content-Type':'text/plain'});res.end('Not found: '+req.url);return;}
    res.writeHead(200,{'Content-Type':ct,'Access-Control-Allow-Origin':'*'});
    res.end(content);
  });
});

initDB().then(()=>{
  server.listen(PORT,()=>{
    console.log(`Server on port ${PORT}`);
    console.log(`Stripe: ${STRIPE_SECRET_KEY?'configured':'NOT configured'}`);
    console.log(`Admin secret: ${ADMIN_SECRET?'SET':'NOT SET'}`);
  });
}).catch(err=>{console.error('DB init failed:',err.message);process.exit(1);});
