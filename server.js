const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;

// Load questions.json into memory at startup, indexed by ID for fast lookup
let QUESTIONS_DATA = null;
let QUESTIONS_BY_ID = {};
let QUESTIONS_BY_TOPIC = {};
try {
  QUESTIONS_DATA = fs.readFileSync(path.join(__dirname, 'questions.json'), 'utf8');
  const parsed = JSON.parse(QUESTIONS_DATA);
  parsed.forEach(q => {
    QUESTIONS_BY_ID[q.id] = q;
    if (!QUESTIONS_BY_TOPIC[q.topic]) QUESTIONS_BY_TOPIC[q.topic] = [];
    QUESTIONS_BY_TOPIC[q.topic].push(q);
  });
  console.log('questions.json loaded: ' + parsed.length + ' questions across ' + Object.keys(QUESTIONS_BY_TOPIC).length + ' topics');
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
const FREE_MOCK_LIMIT = 1;        // lifetime
const MONTHLY_MOCK_LIMIT = 2;     // per calendar month
const ONE_DAY = 86400;
const INSIGHTS_CACHE_SEC = 3600;  // 1 hour

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
        interview_date BIGINT,
        weak_topics TEXT,
        role TEXT,
        onboarded INT DEFAULT 0,
        created_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS question_results (
        user_id BIGINT, question_id TEXT, topic TEXT,
        status TEXT, score INT DEFAULT 0,
        attempt_count INT DEFAULT 1,
        consecutive_high INT DEFAULT 0,
        mastery_stage TEXT,
        next_due BIGINT,
        updated_at BIGINT,
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
      CREATE TABLE IF NOT EXISTS saved_questions (
        user_id BIGINT, question_id TEXT, saved_at BIGINT,
        PRIMARY KEY (user_id, question_id)
      );
      CREATE TABLE IF NOT EXISTS mock_sessions (
        id SERIAL PRIMARY KEY,
        user_id BIGINT,
        format TEXT,
        question_ids JSONB,
        answers JSONB,
        grades JSONB,
        overall_score INT,
        per_topic_scores JSONB,
        started_at BIGINT,
        completed_at BIGINT,
        graded_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS insights_cache (
        user_id BIGINT PRIMARY KEY,
        payload JSONB,
        generated_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS stripe_events (
        id TEXT PRIMARY KEY, processed_at BIGINT
      );
    `);
    // Backfill columns that may not exist on older DBs
    await client.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'free';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS interview_date BIGINT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS weak_topics TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarded INT DEFAULT 0;
      ALTER TABLE question_results ADD COLUMN IF NOT EXISTS attempt_count INT DEFAULT 1;
      ALTER TABLE question_results ADD COLUMN IF NOT EXISTS consecutive_high INT DEFAULT 0;
      ALTER TABLE question_results ADD COLUMN IF NOT EXISTS mastery_stage TEXT;
      ALTER TABLE question_results ADD COLUMN IF NOT EXISTS next_due BIGINT;
    `);
    // Performance indexes
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_qresults_user ON question_results(user_id);
      CREATE INDEX IF NOT EXISTS idx_qresults_due ON question_results(user_id, next_due);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_activity_user ON activity(user_id, date DESC);
      CREATE INDEX IF NOT EXISTS idx_saved_user ON saved_questions(user_id, saved_at DESC);
      CREATE INDEX IF NOT EXISTS idx_mock_user ON mock_sessions(user_id, started_at DESC);
    `);
    console.log('DB ready');
  } finally { client.release(); }
}

// ── AUTH HELPERS ─────────────────────────────────────────────
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
    let b=''; let size=0;
    req.on('data',c=>{ size+=c.length; if(size>65536){req.destroy();return;} b+=c; });
    req.on('end',()=>{ try{resolve(JSON.parse(b))}catch(e){resolve({})} });
  });
}
function readRawBody(req) {
  return new Promise(resolve => {
    const chunks=[]; req.on('data',c=>chunks.push(c)); req.on('end',()=>resolve(Buffer.concat(chunks)));
  });
}
const today = () => new Date().toISOString().slice(0,10);
const nowSec = () => Math.floor(Date.now()/1000);

function shuffle(arr) {
  return arr.map(v=>[Math.random(),v]).sort((a,b)=>a[0]-b[0]).map(v=>v[1]);
}

// ── STRIPE HELPER ────────────────────────────────────────────
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

// ── CLAUDE API HELPER (server-side prompt construction) ─────
function callClaude(systemPrompt, userPrompt, maxTokens) {
  return new Promise((resolve, reject) => {
    const payload = { model: 'claude-sonnet-4-6', max_tokens: maxTokens || 800, messages: [{ role: 'user', content: userPrompt }] };
    if (systemPrompt) payload.system = systemPrompt;
    const data = JSON.stringify(payload);
    const apiReq = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY || '',
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(data)
      }
    }, apiRes => {
      let raw = '';
      apiRes.on('data', c => raw += c);
      apiRes.on('end', () => {
        try {
          const parsed = JSON.parse(raw);
          if (parsed.error) return reject(new Error(parsed.error.message || 'Anthropic API error'));
          resolve(parsed.content?.[0]?.text || '');
        } catch(e) { reject(e); }
      });
    });
    apiReq.on('error', reject);
    apiReq.write(data);
    apiReq.end();
  });
}

function parseJsonFromText(text) {
  if (!text) return null;
  // Strip markdown code fences if Claude wrapped the JSON
  const cleaned = text.replace(/```json\s*|\s*```/g, '').trim();
  try { return JSON.parse(cleaned); } catch(e) { return null; }
}

// ── SPACED REPETITION ───────────────────────────────────────
// Compute mastery stage and next review date from score history
function computeMastery(prevConsecHigh, newScore) {
  const consecHigh = newScore >= 90 ? prevConsecHigh + 1 : 0;
  let stage;
  if (newScore < 60) stage = 'struggling';
  else if (newScore < 80) stage = 'learning';
  else if (newScore < 90) stage = 'strong';
  else stage = consecHigh >= 2 ? 'mastered' : 'strong';
  const intervalDays = { struggling: 1, learning: 3, strong: 7, mastered: 21 }[stage];
  const next_due = nowSec() + intervalDays * ONE_DAY;
  return { stage, consecHigh, next_due };
}

// ── PRACTICE SET BUILDER ────────────────────────────────────
async function buildPracticeSet(userId, n, topic, mode) {
  const now = nowSec();
  const userR = await pool.query('SELECT interview_date FROM users WHERE id=$1', [userId]);
  const interviewDate = userR.rows[0]?.interview_date;
  const isUrgent = interviewDate && (interviewDate - now) < 7 * ONE_DAY && (interviewDate - now) > 0;

  const histR = await pool.query(
    'SELECT question_id, score, mastery_stage, next_due, topic FROM question_results WHERE user_id=$1',
    [userId]
  );
  const seenMap = {};
  histR.rows.forEach(r => { seenMap[r.question_id] = r; });

  const allIds = Object.keys(QUESTIONS_BY_ID);
  const eligibleIds = (topic && topic !== 'All')
    ? allIds.filter(id => QUESTIONS_BY_ID[id].topic === topic)
    : allIds;

  const dueReviews = [];
  const unseen = [];
  const allOthers = [];
  for (const id of eligibleIds) {
    const hist = seenMap[id];
    if (!hist) {
      unseen.push(id);
    } else if (hist.next_due && hist.next_due <= now) {
      dueReviews.push({ id, due: hist.next_due, stage: hist.mastery_stage, last_score: hist.score });
    } else {
      allOthers.push(id);
    }
  }
  dueReviews.sort((a,b) => a.due - b.due);

  // Compute weak topics for new-question weighting
  const topicScores = {};
  histR.rows.forEach(r => {
    if (!topicScores[r.topic]) topicScores[r.topic] = { sum: 0, count: 0 };
    topicScores[r.topic].sum += r.score;
    topicScores[r.topic].count++;
  });
  const weakTopics = Object.entries(topicScores)
    .filter(([_, s]) => s.count >= 2 && s.sum / s.count < 80)
    .map(([t]) => t);

  let result = [];

  if (mode === 'review_weak') {
    const weakOnly = histR.rows
      .filter(r => r.mastery_stage === 'struggling' || r.mastery_stage === 'learning')
      .filter(r => !topic || topic === 'All' || r.topic === topic)
      .sort((a,b) => (a.next_due||0) - (b.next_due||0));
    result = weakOnly.slice(0, n).map(r => ({
      id: r.question_id,
      reason: r.mastery_stage === 'struggling' ? 'Struggling — needs work' : 'Learning',
      stage: r.mastery_stage
    }));
  } else if (mode === 'random') {
    result = shuffle(eligibleIds).slice(0, n).map(id => ({ id, reason: 'Random', stage: null }));
  } else {
    // Smart mode (default)
    const reviewRatio = isUrgent ? 0.7 : 0.5;
    const newRatio = isUrgent ? 0.3 : 0.3;
    const reviewCount = Math.min(Math.floor(n * reviewRatio), dueReviews.length);
    const newCount = isUrgent ? n - reviewCount : Math.floor(n * newRatio);
    const wildcardCount = Math.max(0, n - reviewCount - newCount);

    for (let i = 0; i < reviewCount; i++) {
      const r = dueReviews[i];
      const daysAgo = Math.max(0, Math.round((now - r.due) / ONE_DAY));
      let reason;
      if (r.stage === 'struggling') reason = daysAgo > 0 ? `Review — you missed this ${daysAgo}d ago` : 'Review — you missed this recently';
      else if (r.stage === 'learning') reason = daysAgo > 0 ? `Practicing — last seen ${daysAgo}d ago` : 'Practicing — recent';
      else reason = daysAgo > 0 ? `Reinforcing — last seen ${daysAgo}d ago` : 'Reinforcing';
      result.push({ id: r.id, reason, stage: r.stage });
    }

    const unseenWeak = unseen.filter(id => weakTopics.includes(QUESTIONS_BY_ID[id].topic));
    const unseenOther = unseen.filter(id => !weakTopics.includes(QUESTIONS_BY_ID[id].topic));
    const pickFromWeak = Math.min(Math.floor(newCount * 0.7), unseenWeak.length);
    const pickFromOther = newCount - pickFromWeak;
    const newPicks = [
      ...shuffle(unseenWeak).slice(0, pickFromWeak),
      ...shuffle(unseenOther).slice(0, pickFromOther)
    ];
    for (const id of newPicks) {
      const reasonLabel = weakTopics.includes(QUESTIONS_BY_ID[id].topic) ? 'New — weak area' : 'New';
      result.push({ id, reason: reasonLabel, stage: null });
    }

    if (!isUrgent) {
      const wildcards = shuffle(allOthers).slice(0, wildcardCount);
      for (const id of wildcards) result.push({ id, reason: 'Mixed review', stage: null });
    }

    // Backfill if we're still short
    const used = new Set(result.map(r => r.id));
    const backfillPool = shuffle([...unseen, ...allOthers].filter(id => !used.has(id)));
    while (result.length < n && backfillPool.length > 0) {
      const id = backfillPool.pop();
      result.push({ id, reason: 'New', stage: null });
    }
  }

  return result.slice(0, n).map(r => ({
    ...r,
    question: QUESTIONS_BY_ID[r.id] || null
  })).filter(r => r.question);
}

// ── MOCK INTERVIEW BUILDER ──────────────────────────────────
const MOCK_FORMATS = {
  first_round: {
    label: 'First Round',
    count: 8,
    minutes: 30,
    topicMix: { Accounting: 3, DCF: 2, Enterprise_Value: 1, Valuation: 1, Mergers_MA: 1 }
  },
  superday: {
    label: 'Superday',
    count: 12,
    minutes: 60,
    topicMix: { Accounting: 3, DCF: 3, Enterprise_Value: 2, Valuation: 2, Mergers_MA: 1, LBO: 1 }
  }
};

function buildMockQuestions(format, customConfig) {
  const cfg = format === 'custom' ? customConfig : MOCK_FORMATS[format];
  if (!cfg) return null;
  const picked = [];
  if (format === 'custom') {
    const topics = (customConfig.topics && customConfig.topics.length)
      ? customConfig.topics
      : Object.keys(QUESTIONS_BY_TOPIC);
    const target = Math.min(Math.max(parseInt(customConfig.count)||8, 4), 20);
    const perTopic = Math.ceil(target / topics.length);
    for (const t of topics) {
      const pool = QUESTIONS_BY_TOPIC[t] || [];
      picked.push(...shuffle(pool).slice(0, perTopic).map(q => q.id));
    }
    while (picked.length > target) picked.pop();
  } else {
    for (const [topic, n] of Object.entries(cfg.topicMix)) {
      const pool = QUESTIONS_BY_TOPIC[topic] || [];
      picked.push(...shuffle(pool).slice(0, n).map(q => q.id));
    }
  }
  return shuffle(picked);
}

async function checkMockEligibility(userId) {
  const userR = await pool.query('SELECT plan FROM users WHERE id=$1', [userId]);
  const plan = userR.rows[0]?.plan || 'free';
  if (plan === 'pass') return { ok: true, plan };
  if (plan === 'free') {
    const r = await pool.query('SELECT COUNT(*) FROM mock_sessions WHERE user_id=$1', [userId]);
    const used = parseInt(r.rows[0].count);
    if (used >= FREE_MOCK_LIMIT) {
      return { ok: false, plan, reason: 'free_limit', message: 'Free accounts include 1 mock interview. Upgrade for more.' };
    }
    return { ok: true, plan, remaining: FREE_MOCK_LIMIT - used };
  }
  if (plan === 'monthly') {
    const monthStart = Math.floor(new Date(new Date().setUTCDate(1)).setUTCHours(0,0,0,0) / 1000);
    const r = await pool.query('SELECT COUNT(*) FROM mock_sessions WHERE user_id=$1 AND started_at >= $2', [userId, monthStart]);
    const used = parseInt(r.rows[0].count);
    if (used >= MONTHLY_MOCK_LIMIT) {
      return { ok: false, plan, reason: 'monthly_limit', message: 'Pro Monthly includes 2 mock interviews per month. Upgrade to Recruiting Pass for unlimited.' };
    }
    return { ok: true, plan, remaining: MONTHLY_MOCK_LIMIT - used };
  }
  return { ok: true, plan };
}

// Grade a single answer using server-side prompt
async function gradeMockAnswer(question, userAnswer) {
  if (!userAnswer || !userAnswer.trim()) {
    return { score: 0, verdict: 'Skipped', strengths: '', gaps: 'No answer was given.', concept_gap: null };
  }
  const systemPrompt = `You are an investment banking interview coach grading a candidate's answer to a technical question. Be honest and specific. Respond ONLY with valid JSON in this exact shape, no markdown:
{"score": <integer 0-100>, "verdict": "<one sentence>", "strengths": "<2-3 sentences on what worked>", "gaps": "<2-3 sentences on what is missing or wrong>", "concept_gap": "<short label for the single biggest gap, or null>"}

Scoring rubric: 90-100 = interview-ready answer with all key concepts. 70-89 = correct direction, minor gaps. 50-69 = partial credit, missing key pieces. Below 50 = significantly wrong or confused.`;
  const userPrompt = `Question: ${question.question}\n\nModel answer: ${question.model_answer}\n\nCandidate's answer: "${userAnswer}"\n\nReturn JSON only.`;
  try {
    const text = await callClaude(systemPrompt, userPrompt, 600);
    const parsed = parseJsonFromText(text);
    if (!parsed || typeof parsed.score !== 'number') {
      return { score: 0, verdict: 'Grading error', strengths: '', gaps: '', concept_gap: null };
    }
    return parsed;
  } catch(e) {
    return { score: 0, verdict: 'Grading error: ' + e.message, strengths: '', gaps: '', concept_gap: null };
  }
}

// ── INSIGHTS GENERATOR ──────────────────────────────────────
async function generateInsights(userId) {
  // Check cache
  const cached = await pool.query('SELECT payload, generated_at FROM insights_cache WHERE user_id=$1', [userId]);
  if (cached.rows[0] && (nowSec() - cached.rows[0].generated_at) < INSIGHTS_CACHE_SEC) {
    return cached.rows[0].payload;
  }

  const [resultsR, recentR] = await Promise.all([
    pool.query('SELECT question_id, topic, score FROM question_results WHERE user_id=$1', [userId]),
    pool.query('SELECT question_id, score, created_at FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 40', [userId])
  ]);

  if (resultsR.rows.length < 5) {
    return { ready: false, message: 'Answer at least 5 questions to unlock insights.', answered: resultsR.rows.length };
  }

  const all = resultsR.rows;
  const overall = Math.round(all.reduce((s,r)=>s+r.score, 0) / all.length);

  const byTopic = {};
  all.forEach(r => {
    if (!byTopic[r.topic]) byTopic[r.topic] = [];
    byTopic[r.topic].push(r.score);
  });
  const topicAvgs = Object.entries(byTopic).map(([t, scores]) => ({
    topic: t,
    avg: Math.round(scores.reduce((s,x)=>s+x,0) / scores.length),
    count: scores.length
  })).sort((a,b) => b.avg - a.avg);

  const recent10 = recentR.rows.slice(0, 10);
  const prior10 = recentR.rows.slice(10, 20);
  const recentAvg = recent10.length > 0 ? Math.round(recent10.reduce((s,r)=>s+r.score,0)/recent10.length) : null;
  const priorAvg = prior10.length > 0 ? Math.round(prior10.reduce((s,r)=>s+r.score,0)/prior10.length) : null;
  const trajectory = (recentAvg !== null && priorAvg !== null) ? recentAvg - priorAvg : 0;

  // Frequent concept gaps from recent sessions (if we had concept_gap stored, we'd use it)
  // For now, use weakest topics
  const weakestTopic = topicAvgs[topicAvgs.length - 1];
  const strongestTopic = topicAvgs[0];

  const statsLine = `Total questions answered: ${all.length}. Overall accuracy: ${overall}%. By topic: ${topicAvgs.map(t => `${t.topic.replace('_',' ')} ${t.avg}% (${t.count} attempts)`).join(', ')}. Recent ${recent10.length}: ${recentAvg}%. Prior ${prior10.length}: ${priorAvg}%. Trajectory: ${trajectory >= 0 ? '+' : ''}${trajectory} points.`;

  const insightsPrompt = `You are an investment banking interview coach reviewing a candidate's practice history. Generate exactly three short paragraphs (~25-35 words each) as JSON. Be specific. Reference the actual numbers. No platitudes. No emoji.\n{"diagnosis": "Headline assessment + trajectory direction. Example: 'Your accuracy has climbed from 64% to 82% over the last two weeks — solid trajectory toward interview-ready.'", "weak_pattern": "The specific weak area with concrete framing. Example: 'The remaining gap is concentrated in DCF: at 64% you're below the 80% threshold for confidence on terminal value and WACC.'", "next_action": "ONE concrete action with rough time estimate. Example: 'Next: 8 questions targeted at DCF, about 15 minutes.'"}\n\nStats: ${statsLine}\n\nReturn JSON only, no markdown.`;

  let insights;
  try {
    const text = await callClaude(null, insightsPrompt, 500);
    insights = parseJsonFromText(text);
    if (!insights) insights = { diagnosis: '', weak_pattern: '', next_action: '' };
  } catch(e) {
    insights = { diagnosis: '', weak_pattern: '', next_action: '' };
  }

  // Time-to-mastery: at current improvement rate, how many days to 85%?
  let timeToMastery = null;
  if (overall < 85 && trajectory > 0 && recent10.length >= 5) {
    const improvementPerDay = trajectory / 14;
    if (improvementPerDay > 0.1) {
      timeToMastery = Math.ceil((85 - overall) / improvementPerDay);
      if (timeToMastery > 60 || timeToMastery < 1) timeToMastery = null;
    }
  }

  const payload = {
    ready: true,
    overall,
    topicAvgs,
    trajectory,
    recentAvg,
    priorAvg,
    timeToMastery,
    weakestTopic: weakestTopic ? weakestTopic.topic : null,
    strongestTopic: strongestTopic ? strongestTopic.topic : null,
    ...insights
  };

  await pool.query(
    `INSERT INTO insights_cache (user_id, payload, generated_at) VALUES ($1, $2, $3)
     ON CONFLICT (user_id) DO UPDATE SET payload=$2, generated_at=$3`,
    [userId, JSON.stringify(payload), nowSec()]
  );

  return payload;
}

// ── HTTP SERVER ─────────────────────────────────────────────
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

  // ── AUTH ──────────────────────────────────────────────────
  if (req.method==='POST' && url==='/api/auth/register') {
    try {
      const {email,password,name} = await readBody(req);
      if (!email||!password) return json(res,400,{error:'Email and password required'});
      if (password.length<6) return json(res,400,{error:'Password must be at least 6 characters'});
      const emailLower = email.toLowerCase().trim();
      const existing = await pool.query('SELECT id FROM users WHERE email=$1',[emailLower]);
      if (existing.rows.length>0) return json(res,409,{error:'Email already registered'});
      const id = Date.now() * 1000 + Math.floor(Math.random() * 1000);
      const displayName = name||emailLower.split('@')[0];
      await pool.query('INSERT INTO users (id,email,password_hash,name,plan,onboarded,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [id,emailLower,hashPwd(password),displayName,'free',0,nowSec()]);
      return json(res,200,{token:signToken({userId:id,email:emailLower}),name:displayName,plan:'free',onboarded:false});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/auth/login') {
    try {
      const {email,password} = await readBody(req);
      if (!email||!password) return json(res,400,{error:'Email and password required'});
      const r = await pool.query('SELECT * FROM users WHERE email=$1',[email.toLowerCase().trim()]);
      const user = r.rows[0];
      if (!user||!checkPwd(password,user.password_hash)) return json(res,401,{error:'Invalid email or password'});
      return json(res,200,{token:signToken({userId:user.id,email:user.email}),name:user.name,plan:user.plan||'free',onboarded:!!user.onboarded});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/auth/change-password') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {currentPassword,newPassword} = await readBody(req);
      if(!currentPassword||!newPassword) return json(res,400,{error:'Both fields required'});
      if(newPassword.length<6) return json(res,400,{error:'New password must be at least 6 characters'});
      const r = await pool.query('SELECT password_hash FROM users WHERE id=$1',[user.userId]);
      if(!r.rows[0]||!checkPwd(currentPassword,r.rows[0].password_hash)) return json(res,401,{error:'Current password is incorrect'});
      await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2',[hashPwd(newPassword),user.userId]);
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/auth/update-profile') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {name} = await readBody(req);
      if(!name||!name.trim()) return json(res,400,{error:'Name required'});
      const displayName = name.trim().slice(0,80);
      await pool.query('UPDATE users SET name=$1 WHERE id=$2',[displayName,user.userId]);
      return json(res,200,{ok:true,name:displayName});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // ── ONBOARDING ────────────────────────────────────────────
  // Save the three-question signup interview
  if (req.method==='POST' && url==='/api/onboarding') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {interviewDate, weakTopics, role} = await readBody(req);
      // interviewDate can be null (no date yet), or a unix timestamp (seconds)
      let parsedDate = null;
      if (interviewDate) {
        const n = parseInt(interviewDate);
        if (!isNaN(n) && n > nowSec()) parsedDate = n;
      }
      const topicsStr = Array.isArray(weakTopics) ? weakTopics.join(',') : (weakTopics||'');
      const roleStr = (role||'').toString().slice(0,40);
      await pool.query(
        'UPDATE users SET interview_date=$1, weak_topics=$2, role=$3, onboarded=1 WHERE id=$4',
        [parsedDate, topicsStr, roleStr, user.userId]
      );
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='GET' && url==='/api/onboarding') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const r = await pool.query('SELECT interview_date, weak_topics, role, onboarded FROM users WHERE id=$1', [user.userId]);
      const u = r.rows[0]||{};
      return json(res,200,{
        interviewDate: u.interview_date,
        weakTopics: u.weak_topics ? u.weak_topics.split(',').filter(Boolean) : [],
        role: u.role||'',
        onboarded: !!u.onboarded
      });
    } catch(e){return json(res,500,{error:e.message});}
  }

  // ── PROGRESS ──────────────────────────────────────────────
  if (req.method==='POST' && url==='/api/progress/save-result') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {questionId,topic,status,score} = await readBody(req);
      const scoreNum = parseInt(score)||0;
      // Get prior consec_high
      const prevR = await pool.query('SELECT consecutive_high, attempt_count FROM question_results WHERE user_id=$1 AND question_id=$2', [user.userId, questionId]);
      const prevConsec = prevR.rows[0]?.consecutive_high || 0;
      const prevAttempts = prevR.rows[0]?.attempt_count || 0;
      const mastery = computeMastery(prevConsec, scoreNum);
      await pool.query(
        `INSERT INTO question_results (user_id,question_id,topic,status,score,attempt_count,consecutive_high,mastery_stage,next_due,updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (user_id,question_id) DO UPDATE
           SET status=$4, score=$5, attempt_count=question_results.attempt_count+1,
               consecutive_high=$7, mastery_stage=$8, next_due=$9, updated_at=$10, topic=$3`,
        [user.userId, questionId, topic, status, scoreNum, prevAttempts+1, mastery.consecHigh, mastery.stage, mastery.next_due, nowSec()]
      );
      await pool.query('INSERT INTO sessions (user_id,question_id,topic,score,status,created_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [user.userId,questionId,topic,scoreNum,status,nowSec()]);
      await pool.query(`INSERT INTO activity (user_id,date,questions_answered) VALUES ($1,$2,1)
        ON CONFLICT (user_id,date) DO UPDATE SET questions_answered=activity.questions_answered+1`,
        [user.userId,today()]);
      // Invalidate insights cache (so next /api/insights regenerates)
      await pool.query('DELETE FROM insights_cache WHERE user_id=$1', [user.userId]);
      return json(res,200,{ok:true,mastery:mastery.stage,nextDue:mastery.next_due});
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
        pool.query('SELECT question_id,topic,status,score,mastery_stage,next_due FROM question_results WHERE user_id=$1',[user.userId]),
        pool.query('SELECT last_topic,last_question_index FROM user_state WHERE user_id=$1',[user.userId]),
        pool.query('SELECT question_id,topic,score,status,created_at FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',[user.userId]),
        pool.query('SELECT date,questions_answered FROM activity WHERE user_id=$1 ORDER BY date DESC LIMIT 84',[user.userId]),
        pool.query('SELECT plan, created_at, interview_date, weak_topics, role, onboarded FROM users WHERE id=$1',[user.userId])
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
      const u = userR.rows[0]||{};
      return json(res,200,{
        results: resultsR.rows,
        state,
        history: historyR.rows,
        activity: activityR.rows,
        streak,
        plan: u.plan||'free',
        gradedToday,
        memberSince: u.created_at||null,
        interviewDate: u.interview_date||null,
        weakTopics: u.weak_topics ? u.weak_topics.split(',').filter(Boolean) : [],
        role: u.role||'',
        onboarded: !!u.onboarded
      });
    } catch(e){return json(res,500,{error:e.message});}
  }

  // ── SAVED QUESTIONS (DB-backed) ──────────────────────────
  if (req.method==='POST' && url==='/api/saved/add') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {questionId} = await readBody(req);
      if(!questionId) return json(res,400,{error:'questionId required'});
      if(!QUESTIONS_BY_ID[questionId]) return json(res,404,{error:'Question not found'});
      await pool.query(
        'INSERT INTO saved_questions (user_id,question_id,saved_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
        [user.userId, questionId, nowSec()]
      );
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/saved/remove') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {questionId} = await readBody(req);
      await pool.query('DELETE FROM saved_questions WHERE user_id=$1 AND question_id=$2', [user.userId, questionId]);
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='GET' && url==='/api/saved/list') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const r = await pool.query('SELECT question_id, saved_at FROM saved_questions WHERE user_id=$1 ORDER BY saved_at DESC', [user.userId]);
      // Hydrate with question objects
      const items = r.rows.map(row => ({
        id: row.question_id,
        savedAt: row.saved_at,
        question: QUESTIONS_BY_ID[row.question_id] || null
      })).filter(item => item.question);
      return json(res,200,{items});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // One-shot migration from localStorage to DB on first authenticated load
  if (req.method==='POST' && url==='/api/saved/migrate') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {questionIds} = await readBody(req);
      if(!Array.isArray(questionIds)) return json(res,400,{error:'questionIds array required'});
      let migrated = 0;
      for (const qid of questionIds) {
        if (typeof qid !== 'string' || !QUESTIONS_BY_ID[qid]) continue;
        const r = await pool.query(
          'INSERT INTO saved_questions (user_id,question_id,saved_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
          [user.userId, qid, nowSec()]
        );
        if (r.rowCount > 0) migrated++;
      }
      return json(res,200,{ok:true, migrated});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // ── ADAPTIVE PRACTICE QUEUE ──────────────────────────────
  if (req.method==='GET' && url==='/api/practice/next-set') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const n = Math.min(parseInt(params.get('n'))||10, 30);
      const topic = params.get('topic') || 'All';
      const mode = params.get('mode') || 'smart';
      const set = await buildPracticeSet(user.userId, n, topic, mode);
      return json(res,200,{set, mode, topic, requested:n, delivered:set.length});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // ── MOCK INTERVIEW ───────────────────────────────────────
  if (req.method==='POST' && url==='/api/mock/start') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const elig = await checkMockEligibility(user.userId);
      if (!elig.ok) return json(res,402,elig);
      const {format, count, topics} = await readBody(req);
      const fmt = format || 'first_round';
      if (fmt !== 'first_round' && fmt !== 'superday' && fmt !== 'custom') return json(res,400,{error:'Invalid format'});
      const questionIds = buildMockQuestions(fmt, {count, topics});
      if (!questionIds || questionIds.length === 0) return json(res,500,{error:'Failed to build question set'});
      const r = await pool.query(
        `INSERT INTO mock_sessions (user_id, format, question_ids, answers, started_at)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [user.userId, fmt, JSON.stringify(questionIds), JSON.stringify({}), nowSec()]
      );
      const meta = MOCK_FORMATS[fmt] || { label: 'Custom', minutes: Math.max(15, questionIds.length * 2) };
      return json(res,200,{
        sessionId: r.rows[0].id,
        format: fmt,
        label: meta.label,
        minutes: meta.minutes,
        questions: questionIds.map(id => ({
          id,
          question: QUESTIONS_BY_ID[id]?.question,
          topic: QUESTIONS_BY_ID[id]?.topic
        }))
      });
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/mock/submit') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {sessionId, answers} = await readBody(req);
      if (!sessionId || !answers) return json(res,400,{error:'sessionId and answers required'});
      // Verify ownership
      const r = await pool.query('SELECT question_ids, completed_at FROM mock_sessions WHERE id=$1 AND user_id=$2', [sessionId, user.userId]);
      if (r.rows.length === 0) return json(res,404,{error:'Session not found'});
      if (r.rows[0].completed_at) return json(res,400,{error:'Session already submitted'});
      const questionIds = r.rows[0].question_ids;
      await pool.query(
        'UPDATE mock_sessions SET answers=$1, completed_at=$2 WHERE id=$3',
        [JSON.stringify(answers), nowSec(), sessionId]
      );
      // Grade all answers in parallel
      const gradePromises = questionIds.map(async qid => {
        const ans = answers[qid] || {};
        const grade = await gradeMockAnswer(QUESTIONS_BY_ID[qid], ans.answer || '');
        return { questionId: qid, ...grade, seconds_taken: ans.seconds_taken || 0 };
      });
      const grades = await Promise.all(gradePromises);
      // Compute overall + per-topic
      const validGrades = grades.filter(g => g.verdict !== 'Skipped');
      const overall = validGrades.length > 0
        ? Math.round(validGrades.reduce((s,g)=>s+g.score,0) / validGrades.length)
        : 0;
      const perTopic = {};
      for (const g of grades) {
        const q = QUESTIONS_BY_ID[g.questionId];
        if (!q) continue;
        if (!perTopic[q.topic]) perTopic[q.topic] = { sum: 0, count: 0, items: [] };
        if (g.verdict !== 'Skipped') {
          perTopic[q.topic].sum += g.score;
          perTopic[q.topic].count += 1;
        }
        perTopic[q.topic].items.push(g.questionId);
      }
      const perTopicScores = Object.entries(perTopic).map(([t,d]) => ({
        topic: t,
        avg: d.count > 0 ? Math.round(d.sum/d.count) : 0,
        count: d.count
      }));
      await pool.query(
        'UPDATE mock_sessions SET grades=$1, overall_score=$2, per_topic_scores=$3, graded_at=$4 WHERE id=$5',
        [JSON.stringify(grades), overall, JSON.stringify(perTopicScores), nowSec(), sessionId]
      );
      // Also feed each graded question into question_results so it counts toward mastery
      for (const g of grades) {
        if (g.verdict === 'Skipped') continue;
        const q = QUESTIONS_BY_ID[g.questionId];
        if (!q) continue;
        const prevR = await pool.query('SELECT consecutive_high, attempt_count FROM question_results WHERE user_id=$1 AND question_id=$2', [user.userId, g.questionId]);
        const prevConsec = prevR.rows[0]?.consecutive_high || 0;
        const prevAttempts = prevR.rows[0]?.attempt_count || 0;
        const mastery = computeMastery(prevConsec, g.score);
        await pool.query(
          `INSERT INTO question_results (user_id,question_id,topic,status,score,attempt_count,consecutive_high,mastery_stage,next_due,updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
           ON CONFLICT (user_id,question_id) DO UPDATE
             SET status=$4, score=$5, attempt_count=question_results.attempt_count+1,
                 consecutive_high=$7, mastery_stage=$8, next_due=$9, updated_at=$10, topic=$3`,
          [user.userId, g.questionId, q.topic, g.score>=70?'correct':'incorrect', g.score, prevAttempts+1, mastery.consecHigh, mastery.stage, mastery.next_due, nowSec()]
        );
      }
      // Invalidate insights
      await pool.query('DELETE FROM insights_cache WHERE user_id=$1', [user.userId]);
      return json(res,200,{ok:true, sessionId, overall, perTopicScores, grades});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='GET' && url==='/api/mock/result') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const sessionId = parseInt(params.get('id'));
      if (!sessionId) return json(res,400,{error:'id required'});
      const r = await pool.query('SELECT * FROM mock_sessions WHERE id=$1 AND user_id=$2', [sessionId, user.userId]);
      if (r.rows.length === 0) return json(res,404,{error:'Session not found'});
      const s = r.rows[0];
      // Attach question text
      const grades = (s.grades||[]).map(g => ({
        ...g,
        question_text: QUESTIONS_BY_ID[g.questionId]?.question || '',
        model_answer: QUESTIONS_BY_ID[g.questionId]?.model_answer || '',
        topic: QUESTIONS_BY_ID[g.questionId]?.topic || ''
      }));
      return json(res,200,{
        id: s.id,
        format: s.format,
        overall: s.overall_score,
        perTopicScores: s.per_topic_scores,
        grades,
        answers: s.answers,
        startedAt: s.started_at,
        completedAt: s.completed_at,
        durationSec: s.completed_at && s.started_at ? s.completed_at - s.started_at : null
      });
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='GET' && url==='/api/mock/list') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const r = await pool.query(
        'SELECT id, format, overall_score, started_at, completed_at FROM mock_sessions WHERE user_id=$1 ORDER BY started_at DESC LIMIT 20',
        [user.userId]
      );
      const elig = await checkMockEligibility(user.userId);
      return json(res,200,{sessions: r.rows, eligibility: elig});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='GET' && url==='/api/mock/eligibility') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const elig = await checkMockEligibility(user.userId);
      return json(res,200,elig);
    } catch(e){return json(res,500,{error:e.message});}
  }

  // ── INSIGHTS ─────────────────────────────────────────────
  if (req.method==='GET' && url==='/api/insights') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const payload = await generateInsights(user.userId);
      return json(res,200,payload);
    } catch(e){return json(res,500,{error:e.message});}
  }

  // ── GRADE (legacy free-tier streaming) ───────────────────
  // Kept as-is for now to avoid breaking practice-screen.html flow.
  // TODO: migrate to server-side prompt construction (see /api/mock/submit pattern).
  if (req.method==='POST' && url==='/api/grade') {
    const user=getUser(req);
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
    let body=''; let size=0;
    req.on('data',c=>{ size+=c.length; if(size>65536){req.destroy();return;} body+=c; });
    req.on('end',()=>{
      let parsed; try{parsed=JSON.parse(body);}catch(e){return json(res,400,{error:'Invalid body'});}
      parsed.stream=true;
      res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Access-Control-Allow-Origin':'*','Connection':'keep-alive'});
      const apiReq=https.request({hostname:'api.anthropic.com',path:'/v1/messages',method:'POST',
        headers:{'Content-Type':'application/json','x-api-key':process.env.ANTHROPIC_API_KEY||'','anthropic-version':'2023-06-01'}},
        apiRes=>{ apiRes.on('data',c=>res.write(c)); apiRes.on('end',()=>res.end()); });
      apiReq.on('error',err=>{res.write(`data: ${JSON.stringify({type:'error',message:err.message})}\n\n`);res.end();});
      apiReq.write(JSON.stringify(parsed)); apiReq.end();
    }); return;
  }

  // ── STRIPE ───────────────────────────────────────────────
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

  if (req.method==='POST' && url==='/api/stripe/portal') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    if(!STRIPE_SECRET_KEY) return json(res,503,{error:'Stripe not configured'});
    try {
      const r = await pool.query('SELECT stripe_customer_id FROM users WHERE id=$1',[user.userId]);
      const customerId = r.rows[0]?.stripe_customer_id;
      if(!customerId) return json(res,400,{error:'No billing account found. Please contact support.'});
      const session = await stripeRequest('POST','/v1/billing_portal/sessions',{
        customer: customerId,
        return_url: APP_URL+'/billing.html'
      });
      if(session.error) return json(res,400,{error:session.error.message});
      return json(res,200,{url:session.url});
    } catch(e){return json(res,500,{error:e.message});}
  }

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

  // ── ADMIN ────────────────────────────────────────────────
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

  // ── QUESTIONS DATA ───────────────────────────────────────
  if (url==='/api/questions') {
    if (!QUESTIONS_DATA) return json(res, 503, { error: 'questions.json not loaded — ensure the file is committed to your repository' });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=3600' });
    res.end(QUESTIONS_DATA);
    return;
  }

  // ── STATIC FILES ─────────────────────────────────────────
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
    console.log(`Anthropic key: ${process.env.ANTHROPIC_API_KEY?'SET':'NOT SET'}`);
  });
}).catch(err=>{console.error('DB init failed:',err.message);process.exit(1);});
