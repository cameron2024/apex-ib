const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const { WebSocketServer, WebSocket } = require('ws');

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
    // ── SOCIAL TABLES ────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS follows (
        follower_id BIGINT,
        following_id BIGINT,
        created_at BIGINT,
        PRIMARY KEY (follower_id, following_id)
      );
      CREATE TABLE IF NOT EXISTS feed_events (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT,
        type TEXT,
        payload JSONB,
        created_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS feed_reactions (
        id BIGSERIAL PRIMARY KEY,
        event_id BIGINT,
        user_id BIGINT,
        emoji TEXT,
        created_at BIGINT,
        UNIQUE (event_id, user_id, emoji)
      );
      CREATE TABLE IF NOT EXISTS feed_comments (
        id BIGSERIAL PRIMARY KEY,
        event_id BIGINT,
        user_id BIGINT,
        body TEXT,
        created_at BIGINT
      );
    `);
    // ── SCHOOL / CONFERENCE TABLES ───────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS bug_reports (
        id SERIAL PRIMARY KEY,
        user_id BIGINT,
        type TEXT, severity TEXT,
        title TEXT, description TEXT,
        question TEXT, page TEXT, user_agent TEXT,
        created_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS schools (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        domain TEXT UNIQUE NOT NULL,
        conference TEXT,
        logo_url TEXT
      );
      CREATE TABLE IF NOT EXISTS school_memberships (
        user_id BIGINT PRIMARY KEY,
        school_id INT,
        verified_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS conference_challenges (
        id SERIAL PRIMARY KEY,
        conference TEXT NOT NULL,
        title TEXT NOT NULL,
        starts_at BIGINT,
        ends_at BIGINT,
        status TEXT DEFAULT 'upcoming'
      );
      CREATE TABLE IF NOT EXISTS challenge_scores (
        challenge_id INT,
        school_id INT,
        total_score BIGINT DEFAULT 0,
        participants INT DEFAULT 0,
        updated_at BIGINT,
        PRIMARY KEY (challenge_id, school_id)
      );
      CREATE TABLE IF NOT EXISTS badges (
        id TEXT PRIMARY KEY,
        name TEXT,
        description TEXT,
        icon TEXT,
        type TEXT
      );
      CREATE TABLE IF NOT EXISTS user_badges (
        user_id BIGINT,
        badge_id TEXT,
        awarded_at BIGINT,
        PRIMARY KEY (user_id, badge_id)
      );
    `);
    // ── STUDY PARTY TABLES ───────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS study_parties (
        id TEXT PRIMARY KEY,
        host_id BIGINT,
        status TEXT DEFAULT 'lobby',
        topic TEXT,
        time_limit_sec INT,
        question_ids JSONB,
        current_question_index INT DEFAULT 0,
        created_at BIGINT,
        started_at BIGINT,
        completed_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS party_members (
        party_id TEXT,
        user_id BIGINT,
        joined_at BIGINT,
        status TEXT DEFAULT 'active',
        PRIMARY KEY (party_id, user_id)
      );
      CREATE TABLE IF NOT EXISTS party_answers (
        party_id TEXT,
        user_id BIGINT,
        question_id TEXT,
        answer_text TEXT,
        score INT,
        grade_payload JSONB,
        submitted_at BIGINT,
        PRIMARY KEY (party_id, user_id, question_id)
      );
    `);
    // ── INDEXES ──────────────────────────────────────────────
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id);
      CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following_id);
      CREATE INDEX IF NOT EXISTS idx_feed_events_user ON feed_events(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_feed_comments_event ON feed_comments(event_id);
      CREATE INDEX IF NOT EXISTS idx_feed_reactions_event ON feed_reactions(event_id);
      CREATE INDEX IF NOT EXISTS idx_party_members_party ON party_members(party_id);
      CREATE INDEX IF NOT EXISTS idx_party_answers_party ON party_answers(party_id, question_id);
      CREATE INDEX IF NOT EXISTS idx_challenge_scores_challenge ON challenge_scores(challenge_id);
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
      ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_data TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_private INT DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS visibility TEXT DEFAULT 'public';
      UPDATE users SET is_private=0 WHERE is_private IS NULL;
      UPDATE users SET visibility='public' WHERE visibility IS NULL;
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
    if (!process.env.ANTHROPIC_API_KEY) {
      return reject(new Error('ANTHROPIC_API_KEY is not set on the server.'));
    }
    const payload = { model: 'claude-haiku-4-5-20251001', max_tokens: maxTokens || 800, messages: [{ role: 'user', content: userPrompt }] };
    if (systemPrompt) payload.system = systemPrompt;
    const data = JSON.stringify(payload);
    const apiReq = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
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
          if (apiRes.statusCode !== 200) return reject(new Error(`Anthropic API error (${apiRes.statusCode}): ${raw.slice(0,200)}`));
          const text = parsed.content?.[0]?.text || '';
          if (!text) return reject(new Error('Empty response from grading service — please try again.'));
          resolve(text);
        } catch(e) { reject(new Error('Could not parse grading response — please try again.')); }
      });
    });
    apiReq.on('error', err => reject(new Error('Network error reaching grading service: ' + err.message)));
    apiReq.write(data);
    apiReq.end();
  });
}

function parseJsonFromText(text) {
  if (!text) return null;
  // Find the outermost { } block regardless of surrounding text or markdown
  const start = text.indexOf('{');
  if (start === -1) return null;
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (esc) { esc = false; continue; }
    if (c === '\\' && inStr) { esc = true; continue; }
    if (c === '"') { inStr = !inStr; continue; }
    if (!inStr) {
      if (c === '{') depth++;
      else if (c === '}') { depth--; if (depth === 0) { try { return JSON.parse(text.slice(start, i+1)); } catch(_) { return null; } } }
    }
  }
  // Truncated — try to salvage
  if (depth > 0) {
    try {
      let s = text.slice(start).replace(/,\s*"[^"]*$/, '').replace(/,\s*$/, '');
      return JSON.parse(s + '}'.repeat(depth));
    } catch(_) { return null; }
  }
  return null;
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

  // ── PER-TOPIC DIFFICULTY UNLOCK ──────────────────────────
  // For each topic, compute which difficulty levels are unlocked
  // based on how many basics have been seen and avg score on them.
  function getUnlockedDifficulties(topicFilter) {
    const topicQuestions = allIds.filter(id => {
      const q = QUESTIONS_BY_ID[id];
      return !topicFilter || topicFilter === 'All' || q.topic === topicFilter;
    });
    const basics = topicQuestions.filter(id => QUESTIONS_BY_ID[id].difficulty === 'basic');
    const intermediates = topicQuestions.filter(id => QUESTIONS_BY_ID[id].difficulty === 'intermediate');

    const seenBasics = basics.filter(id => seenMap[id]);
    const seenIntermediates = intermediates.filter(id => seenMap[id]);

    const basicScores = seenBasics.map(id => seenMap[id].score).filter(s => s != null);
    const basicAvg = basicScores.length > 0 ? basicScores.reduce((a,b)=>a+b,0)/basicScores.length : 0;
    const basicSeenRatio = basics.length > 0 ? seenBasics.length / basics.length : 0;

    const intermScores = seenIntermediates.map(id => seenMap[id].score).filter(s => s != null);
    const intermAvg = intermScores.length > 0 ? intermScores.reduce((a,b)=>a+b,0)/intermScores.length : 0;
    const intermSeenRatio = intermediates.length > 0 ? seenIntermediates.length / intermediates.length : 0;

    const unlocked = new Set(['basic']);
    // Unlock intermediate: avg ≥ 70 on basics OR seen ≥ 60% of basics
    if (seenBasics.length > 0 && (basicAvg >= 70 || basicSeenRatio >= 0.6)) {
      unlocked.add('intermediate');
    }
    // Unlock hard: avg ≥ 75 on intermediate OR seen ≥ 60% of intermediates
    if (unlocked.has('intermediate') && seenIntermediates.length > 0 && (intermAvg >= 75 || intermSeenRatio >= 0.6)) {
      unlocked.add('hard');
    }
    return unlocked;
  }

  // Build per-topic unlock map for 'All' mode
  const topicUnlockMap = {};
  const allTopics = [...new Set(allIds.map(id => QUESTIONS_BY_ID[id].topic))];
  if (!topic || topic === 'All') {
    allTopics.forEach(t => { topicUnlockMap[t] = getUnlockedDifficulties(t); });
  } else {
    topicUnlockMap[topic] = getUnlockedDifficulties(topic);
  }

  function isDifficultyUnlocked(qId) {
    const q = QUESTIONS_BY_ID[qId];
    const unlocked = topicUnlockMap[q.topic];
    return unlocked ? unlocked.has(q.difficulty) : true;
  }

  // Order unseen questions: basic first, then intermediate, then hard
  const DIFF_ORDER = { basic: 0, intermediate: 1, hard: 2 };
  function sortByDifficulty(ids) {
    return [...ids].sort((a, b) => {
      const da = DIFF_ORDER[QUESTIONS_BY_ID[a].difficulty] ?? 1;
      const db = DIFF_ORDER[QUESTIONS_BY_ID[b].difficulty] ?? 1;
      return da - db;
    });
  }

  const dueReviews = [];
  const unseen = [];
  const allOthers = [];
  for (const id of eligibleIds) {
    const hist = seenMap[id];
    if (!hist) {
      // Only include unseen questions at unlocked difficulty levels
      if (isDifficultyUnlocked(id)) unseen.push(id);
    } else if (hist.next_due && hist.next_due <= now) {
      dueReviews.push({ id, due: hist.next_due, stage: hist.mastery_stage, last_score: hist.score });
    } else {
      allOthers.push(id);
    }
  }
  dueReviews.sort((a,b) => a.due - b.due);

  // Sort unseen: basic first, then intermediate, then hard within each difficulty shuffle
  const unseenByDiff = { basic: [], intermediate: [], hard: [] };
  unseen.forEach(id => {
    const d = QUESTIONS_BY_ID[id].difficulty || 'basic';
    (unseenByDiff[d] = unseenByDiff[d] || []).push(id);
  });
  // Shuffle within each tier, then concat in order
  const unseenOrdered = [
    ...shuffle(unseenByDiff.basic || []),
    ...shuffle(unseenByDiff.intermediate || []),
    ...shuffle(unseenByDiff.hard || []),
  ];

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

    const unseenWeak = unseenOrdered.filter(id => weakTopics.includes(QUESTIONS_BY_ID[id].topic));
    const unseenOther = unseenOrdered.filter(id => !weakTopics.includes(QUESTIONS_BY_ID[id].topic));
    const pickFromWeak = Math.min(Math.floor(newCount * 0.7), unseenWeak.length);
    const pickFromOther = newCount - pickFromWeak;
    // Take from front (already sorted basic→intermediate→hard, shuffled within tier)
    const newPicks = [
      ...unseenWeak.slice(0, pickFromWeak),
      ...unseenOther.slice(0, pickFromOther)
    ];
    for (const id of newPicks) {
      const reasonLabel = weakTopics.includes(QUESTIONS_BY_ID[id].topic) ? 'New — weak area' : 'New';
      result.push({ id, reason: reasonLabel, stage: null });
    }

    if (!isUrgent) {
      const wildcards = shuffle(allOthers).slice(0, wildcardCount);
      for (const id of wildcards) result.push({ id, reason: 'Mixed review', stage: null });
    }

    // Backfill if we're still short — use difficulty order then wildcards
    const used = new Set(result.map(r => r.id));
    const backfillPool = [
      ...unseenOrdered.filter(id => !used.has(id)),
      ...shuffle(allOthers.filter(id => !used.has(id)))
    ];
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

  // Recruiting Pass — unlimited
  if (plan === 'pass') return { ok: true, plan };

  // Free — 1 mock lifetime
  if (plan === 'free') {
    const r = await pool.query('SELECT COUNT(*) FROM mock_sessions WHERE user_id=$1', [userId]);
    const used = parseInt(r.rows[0].count);
    if (used >= FREE_MOCK_LIMIT) {
      return { ok: false, plan, reason: 'free_limit', message: 'Free accounts include 1 lifetime mock interview. Upgrade to Pro for 1 mock every 24 hours.' };
    }
    return { ok: true, plan, remaining: FREE_MOCK_LIMIT - used };
  }

  // Pro — 1 mock per 24h rolling window starting from when the last mock COMPLETED
  if (plan === 'monthly') {
    const r = await pool.query(
      'SELECT completed_at FROM mock_sessions WHERE user_id=$1 AND completed_at IS NOT NULL ORDER BY completed_at DESC LIMIT 1',
      [userId]
    );
    const lastCompleted = r.rows[0] ? parseInt(r.rows[0].completed_at) : 0;
    const now = nowSec();
    const cooldownUntil = lastCompleted + ONE_DAY;
    if (lastCompleted && now < cooldownUntil) {
      const secsLeft = cooldownUntil - now;
      const hoursLeft = Math.floor(secsLeft / 3600);
      const minsLeft = Math.ceil((secsLeft % 3600) / 60);
      const niceTime = hoursLeft > 0 ? `${hoursLeft}h ${minsLeft}m` : `${minsLeft}m`;
      return {
        ok: false, plan, reason: 'daily_limit',
        message: `Next mock available in ${niceTime}.`,
        nextAvailableAt: cooldownUntil,
        secondsRemaining: secsLeft
      };
    }
    return { ok: true, plan };
  }

  return { ok: true, plan };
}

// Grade a single answer using server-side prompt
async function gradeMockAnswer(question, userAnswer) {
  if (!userAnswer || !userAnswer.trim()) {
    return { score: 0, verdict: 'Skipped', strengths: '', gaps: 'No answer was given.', concept_gap: null };
  }
  const systemPrompt = `You are an investment banking interview coach grading a candidate's answer to a technical question. Be honest and specific. Your response MUST start with { and end with }. Output raw JSON only — no markdown, no explanation, no text before or after the JSON object:
{"score": <integer 0-100>, "verdict": "<one sentence>", "strengths": "<2-3 sentences on what worked>", "gaps": "<2-3 sentences on what is missing or wrong>", "concept_gap": "<short label for the single biggest gap, or null>"}

Scoring rubric: 90-100 = interview-ready answer with all key concepts. 70-89 = correct direction, minor gaps. 50-69 = partial credit, missing key pieces. Below 50 = significantly wrong or confused.`;
  const userPrompt = `Question: ${question.question}\n\nModel answer: ${question.model_answer}\n\nCandidate's answer: "${userAnswer}"\n\nReturn JSON only.`;
  try {
    const text = await callClaude(systemPrompt, userPrompt, 1024);
    const parsed = parseJsonFromText(text);
    if (!parsed || typeof parsed.score !== 'number') {
      return { score: 0, verdict: 'Grading error — malformed response.', strengths: '', gaps: 'Please try again.', concept_gap: null };
    }
    return parsed;
  } catch(e) {
    return { score: 0, verdict: 'Grading unavailable — ' + e.message, strengths: '', gaps: 'Please try again in a moment.', concept_gap: null };
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
    const text = await callClaude(null, insightsPrompt, 1024);
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

// ── CONFERENCE LOGO MAP ──────────────────────────────────────
const CONFERENCE_LOGOS = {
  'Ivy League':   'https://upload.wikimedia.org/wikipedia/en/thumb/0/07/Ivy_League_logo.svg/320px-Ivy_League_logo.svg.png',
  'NESCAC':       'https://upload.wikimedia.org/wikipedia/en/thumb/5/58/NESCAC_logo.svg/320px-NESCAC_logo.svg.png',
  'ACC':          'https://upload.wikimedia.org/wikipedia/commons/thumb/6/6e/Atlantic_Coast_Conference_logo.svg/320px-Atlantic_Coast_Conference_logo.svg.png',
  'Big Ten':      'https://upload.wikimedia.org/wikipedia/commons/thumb/9/91/Big_Ten_Conference_logo.svg/320px-Big_Ten_Conference_logo.svg.png',
  'SEC':          'https://upload.wikimedia.org/wikipedia/commons/thumb/2/2e/Southeastern_Conference_logo.svg/320px-Southeastern_Conference_logo.svg.png',
  'Pac-12':       'https://upload.wikimedia.org/wikipedia/commons/thumb/b/b7/Pac-12_Conference_logo.svg/320px-Pac-12_Conference_logo.svg.png',
  'Independent':  null,
};

// ── SCHOOL DOMAIN LOOKUP ─────────────────────────────────────
const SCHOOL_SEED = [
  // Ivy League
  { name: 'Harvard University', domain: 'harvard.edu', conference: 'Ivy League' },
  { name: 'Yale University', domain: 'yale.edu', conference: 'Ivy League' },
  { name: 'Princeton University', domain: 'princeton.edu', conference: 'Ivy League' },
  { name: 'Columbia University', domain: 'columbia.edu', conference: 'Ivy League' },
  { name: 'University of Pennsylvania', domain: 'upenn.edu', conference: 'Ivy League' },
  { name: 'Brown University', domain: 'brown.edu', conference: 'Ivy League' },
  { name: 'Dartmouth College', domain: 'dartmouth.edu', conference: 'Ivy League' },
  { name: 'Cornell University', domain: 'cornell.edu', conference: 'Ivy League' },
  // NESCAC
  { name: 'Amherst College', domain: 'amherst.edu', conference: 'NESCAC' },
  { name: 'Williams College', domain: 'williams.edu', conference: 'NESCAC' },
  { name: 'Middlebury College', domain: 'middlebury.edu', conference: 'NESCAC' },
  { name: 'Bowdoin College', domain: 'bowdoin.edu', conference: 'NESCAC' },
  { name: 'Colby College', domain: 'colby.edu', conference: 'NESCAC' },
  { name: 'Hamilton College', domain: 'hamilton.edu', conference: 'NESCAC' },
  { name: 'Trinity College', domain: 'trincoll.edu', conference: 'NESCAC' },
  { name: 'Wesleyan University', domain: 'wesleyan.edu', conference: 'NESCAC' },
  { name: 'Tufts University', domain: 'tufts.edu', conference: 'NESCAC' },
  { name: 'Bates College', domain: 'bates.edu', conference: 'NESCAC' },
  { name: 'Connecticut College', domain: 'conncoll.edu', conference: 'NESCAC' },
  // ACC
  { name: 'Duke University', domain: 'duke.edu', conference: 'ACC' },
  { name: 'University of North Carolina', domain: 'unc.edu', conference: 'ACC' },
  { name: 'Georgetown University', domain: 'georgetown.edu', conference: 'ACC' },
  { name: 'Boston College', domain: 'bc.edu', conference: 'ACC' },
  { name: 'University of Virginia', domain: 'virginia.edu', conference: 'ACC' },
  { name: 'Wake Forest University', domain: 'wfu.edu', conference: 'ACC' },
  { name: 'Notre Dame', domain: 'nd.edu', conference: 'ACC' },
  // Big Ten
  { name: 'University of Michigan', domain: 'umich.edu', conference: 'Big Ten' },
  { name: 'Northwestern University', domain: 'northwestern.edu', conference: 'Big Ten' },
  { name: 'University of Chicago', domain: 'uchicago.edu', conference: 'Big Ten' },
  { name: 'Penn State University', domain: 'psu.edu', conference: 'Big Ten' },
  { name: 'Ohio State University', domain: 'osu.edu', conference: 'Big Ten' },
  { name: 'University of Wisconsin', domain: 'wisc.edu', conference: 'Big Ten' },
  { name: 'University of Minnesota', domain: 'umn.edu', conference: 'Big Ten' },
  { name: 'Indiana University', domain: 'indiana.edu', conference: 'Big Ten' },
  { name: 'Purdue University', domain: 'purdue.edu', conference: 'Big Ten' },
  { name: 'University of Illinois', domain: 'illinois.edu', conference: 'Big Ten' },
  // SEC
  { name: 'Vanderbilt University', domain: 'vanderbilt.edu', conference: 'SEC' },
  { name: 'University of Georgia', domain: 'uga.edu', conference: 'SEC' },
  { name: 'University of Florida', domain: 'ufl.edu', conference: 'SEC' },
  { name: 'University of Alabama', domain: 'ua.edu', conference: 'SEC' },
  { name: 'University of Texas', domain: 'utexas.edu', conference: 'SEC' },
  // Other top schools
  { name: 'MIT', domain: 'mit.edu', conference: 'Independent' },
  { name: 'Stanford University', domain: 'stanford.edu', conference: 'Pac-12' },
  { name: 'University of California Berkeley', domain: 'berkeley.edu', conference: 'Pac-12' },
  { name: 'UCLA', domain: 'ucla.edu', conference: 'Pac-12' },
  { name: 'Carnegie Mellon University', domain: 'cmu.edu', conference: 'Independent' },
  { name: 'NYU', domain: 'nyu.edu', conference: 'Independent' },
  { name: 'Emory University', domain: 'emory.edu', conference: 'Independent' },
  { name: 'Washington University in St. Louis', domain: 'wustl.edu', conference: 'Independent' },
  { name: 'Rice University', domain: 'rice.edu', conference: 'Independent' },
  { name: 'Tulane University', domain: 'tulane.edu', conference: 'Independent' },
];

async function seedSchools() {
  for (const s of SCHOOL_SEED) {
    const logoUrl = CONFERENCE_LOGOS[s.conference] || null;
    await pool.query(
      `INSERT INTO schools (name, domain, conference, logo_url) VALUES ($1, $2, $3, $4)
       ON CONFLICT (domain) DO UPDATE SET name=$1, conference=$3, logo_url=$4`,
      [s.name, s.domain, s.conference, logoUrl]
    );
  }
}

async function detectSchoolFromEmail(email) {
  const domain = email.split('@')[1];
  if (!domain || !domain.endsWith('.edu')) return null;
  const r = await pool.query('SELECT id, name, conference FROM schools WHERE domain=$1', [domain]);
  return r.rows[0] || null;
}

async function linkUserToSchool(userId, schoolId) {
  await pool.query(
    `INSERT INTO school_memberships (user_id, school_id, verified_at) VALUES ($1, $2, $3)
     ON CONFLICT (user_id) DO NOTHING`,
    [userId, schoolId, nowSec()]
  );
}

// ── FEED EVENT EMITTER ───────────────────────────────────────
async function emitFeedEvent(userId, type, payload) {
  await pool.query(
    'INSERT INTO feed_events (user_id, type, payload, created_at) VALUES ($1, $2, $3, $4)',
    [userId, type, JSON.stringify(payload), nowSec()]
  );
}

// ── BADGE AWARD ──────────────────────────────────────────────
async function awardBadge(userId, badgeId) {
  await pool.query(
    `INSERT INTO user_badges (user_id, badge_id, awarded_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
    [userId, badgeId, nowSec()]
  );
  const badgeR = await pool.query('SELECT * FROM badges WHERE id=$1', [badgeId]);
  if (badgeR.rows[0]) {
    await emitFeedEvent(userId, 'badge_earned', { badge: badgeR.rows[0] });
  }
}

// ── PARTY CODE GENERATOR ─────────────────────────────────────
function generatePartyCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ── WEBSOCKET PARTY STATE ────────────────────────────────────
// partyClients: Map<partyId, Map<userId, WebSocket>>
const partyClients = new Map();

function broadcastToParty(partyId, message, excludeUserId = null) {
  const clients = partyClients.get(partyId);
  if (!clients) return;
  const data = JSON.stringify(message);
  for (const [uid, ws] of clients) {
    if (excludeUserId && uid === excludeUserId) continue;
    if (ws.readyState === WebSocket.OPEN) ws.send(data);
  }
}

function getPartyMemberCount(partyId) {
  return partyClients.get(partyId)?.size || 0;
}

// ── STREAK HELPER ────────────────────────────────────────────
async function computeStreak(userId) {
  const actR = await pool.query(
    'SELECT date FROM activity WHERE user_id=$1 ORDER BY date DESC LIMIT 365', [userId]
  );
  const actDates = new Set(actR.rows.map(r => r.date));
  let streak = 0;
  for (let i = 0; i < 365; i++) {
    const d = new Date(); d.setDate(d.getDate() - i);
    const ds = d.toISOString().slice(0, 10);
    if (actDates.has(ds)) streak++;
    else if (i > 0) break;
  }
  return streak;
}

// Milestone streak values that earn a feed event
const STREAK_MILESTONES = new Set([3, 7, 14, 30, 60, 100, 365]);

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
      // Auto-detect school from .edu email
      let schoolInfo = null;
      const school = await detectSchoolFromEmail(emailLower);
      if (school) {
        await linkUserToSchool(id, school.id);
        schoolInfo = { name: school.name, conference: school.conference };
      }
      return json(res,200,{token:signToken({userId:id,email:emailLower}),name:displayName,plan:'free',onboarded:false,school:schoolInfo,user:{id,name:displayName,email:emailLower,plan:'free'}});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/auth/login') {
    try {
      const {email,password} = await readBody(req);
      if (!email||!password) return json(res,400,{error:'Email and password required'});
      const r = await pool.query('SELECT * FROM users WHERE email=$1',[email.toLowerCase().trim()]);
      const user = r.rows[0];
      if (!user||!checkPwd(password,user.password_hash)) return json(res,401,{error:'Invalid email or password'});
      return json(res,200,{token:signToken({userId:user.id,email:user.email}),name:user.name,plan:user.plan||'free',onboarded:!!user.onboarded,user:{id:user.id,name:user.name,email:user.email,plan:user.plan||'free'}});
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

  // GET /api/auth/privacy — get own privacy settings
  if (req.method==='GET' && url==='/api/auth/privacy') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const r = await pool.query('SELECT is_private, visibility FROM users WHERE id=$1', [user.userId]);
      const u = r.rows[0] || {};
      return json(res,200,{ isPrivate: !!u.is_private, visibility: u.visibility || 'public' });
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/auth/privacy — save privacy settings
  if (req.method==='POST' && url==='/api/auth/privacy') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {isPrivate, visibility} = await readBody(req);
      const validVisibility = ['public','friends','school','school_and_friends'];
      const vis = validVisibility.includes(visibility) ? visibility : 'public';
      await pool.query(
        'UPDATE users SET is_private=$1, visibility=$2 WHERE id=$3',
        [isPrivate ? 1 : 0, vis, user.userId]
      );
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/auth/save-avatar
  if (req.method==='POST' && url==='/api/auth/save-avatar') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {avatarData} = await readBody(req);
      if (!avatarData) return json(res,400,{error:'avatarData required'});
      if (avatarData.length > 700000) return json(res,400,{error:'Image too large. Please use a smaller photo.'});
      await pool.query('UPDATE users SET avatar_data=$1 WHERE id=$2', [avatarData, user.userId]);
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // DELETE /api/auth/remove-avatar
  if (req.method==='DELETE' && url==='/api/auth/remove-avatar') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      await pool.query('UPDATE users SET avatar_data=NULL WHERE id=$1', [user.userId]);
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/auth/avatar?id=xxx
  if (req.method==='GET' && url==='/api/auth/avatar') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const targetId = params.get('id') || user.userId;
      const r = await pool.query('SELECT avatar_data FROM users WHERE id=$1', [targetId]);
      return json(res,200,{avatarData: r.rows[0]?.avatar_data || null});
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
      const actInsert = await pool.query(`INSERT INTO activity (user_id,date,questions_answered) VALUES ($1,$2,1)
        ON CONFLICT (user_id,date) DO UPDATE SET questions_answered=activity.questions_answered+1 RETURNING questions_answered`,
        [user.userId,today()]);
      const questionsToday = parseInt(actInsert.rows[0]?.questions_answered || 1);
      // Invalidate insights cache
      await pool.query('DELETE FROM insights_cache WHERE user_id=$1', [user.userId]);

      // ── FEED EVENTS ──────────────────────────────────────
      // session_complete: upsert into the most recent event within 30 min, else create new
      const thirtyMinAgo = Math.floor(Date.now()/1000) - 1800;
      const recentEvent = await pool.query(
        `SELECT id FROM feed_events WHERE user_id=$1 AND type='session_complete' AND created_at >= $2 ORDER BY created_at DESC LIMIT 1`,
        [user.userId, thirtyMinAgo]
      );
      const todaySessionsR = await pool.query(
        'SELECT score FROM sessions WHERE user_id=$1 AND created_at >= $2',
        [user.userId, Math.floor(new Date().setHours(0,0,0,0)/1000)]
      );
      const scores = todaySessionsR.rows.map(r => r.score);
      const avgScore = scores.length > 0 ? Math.round(scores.reduce((a,b)=>a+b,0)/scores.length) : 0;
      const sessionPayload = JSON.stringify({ questionsAnswered: questionsToday, avgScore, topic: topic || 'All' });
      if (recentEvent.rows[0]) {
        // Update the existing event so the feed shows fresh numbers without flooding
        await pool.query('UPDATE feed_events SET payload=$1, created_at=$2 WHERE id=$3',
          [sessionPayload, nowSec(), recentEvent.rows[0].id]);
      } else {
        await emitFeedEvent(user.userId, 'session_complete', { questionsAnswered: questionsToday, avgScore, topic: topic || 'All' });
      }

      // 2. streak milestone
      const streak = await computeStreak(user.userId);
      if (STREAK_MILESTONES.has(streak)) {
        // Only emit once per day per milestone (check if we already fired it today)
        const already = await pool.query(
          `SELECT id FROM feed_events WHERE user_id=$1 AND type='streak'
           AND (payload->>'streakDays')::int=$2 AND created_at >= $3`,
          [user.userId, streak, Math.floor(Date.now()/1000) - 86400]
        );
        if (already.rows.length === 0) {
          await emitFeedEvent(user.userId, 'streak', { streakDays: streak });
        }
      }

      // 3. mastery — emit when a question first reaches 'mastered'
      if (mastery.stage === 'mastered' && (prevConsec < 2)) {
        const masteredCount = await pool.query(
          `SELECT COUNT(*) FROM question_results WHERE user_id=$1 AND mastery_stage='mastered'`,
          [user.userId]
        );
        await emitFeedEvent(user.userId, 'mastery', {
          topic: topic,
          questionId: questionId,
          questionCount: parseInt(masteredCount.rows[0].count),
        });
      }

      return json(res,200,{ok:true,mastery:mastery.stage,nextDue:mastery.next_due,streak});
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
        pool.query('SELECT plan, created_at, interview_date, weak_topics, role, onboarded, avatar_data FROM users WHERE id=$1',[user.userId])
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
        onboarded: !!u.onboarded,
        avatarData: u.avatar_data||null,
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
      // ── FEED EVENT: mock session complete ──
      await emitFeedEvent(user.userId, 'session_complete', {
        questionsAnswered: questionIds.length,
        avgScore: overall,
        topic: 'Mock Interview',
        isMock: true,
      });
      // Streak check
      const mockStreak = await computeStreak(user.userId);
      if (STREAK_MILESTONES.has(mockStreak)) {
        const already = await pool.query(
          `SELECT id FROM feed_events WHERE user_id=$1 AND type='streak'
           AND (payload->>'streakDays')::int=$2 AND created_at >= $3`,
          [user.userId, mockStreak, Math.floor(Date.now()/1000) - 86400]
        );
        if (already.rows.length === 0) {
          await emitFeedEvent(user.userId, 'streak', { streakDays: mockStreak });
        }
      }
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
            return json(res,402,{
              error:'limit_reached',
              flashcard_mode: true,
              message:`You've used all ${FREE_DAILY_LIMIT} free grades today. You can still study in flashcard mode — questions and model answers, no AI grading. Upgrade to Pro for unlimited graded answers.`,
              plan:'free',
              gradedToday:count
            });
          }
        }
      } catch(e){return json(res,500,{error:e.message});}
    }
    let body=''; let size=0;
    req.on('data',c=>{ size+=c.length; if(size>65536){req.destroy();return;} body+=c; });
    req.on('end',()=>{
      let parsed; try{parsed=JSON.parse(body);}catch(e){return json(res,400,{error:'Invalid body'});}
      if (!process.env.ANTHROPIC_API_KEY) {
        res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Access-Control-Allow-Origin':'*','Connection':'keep-alive'});
        res.write(`data: ${JSON.stringify({type:'error',message:'ANTHROPIC_API_KEY is not set on the server.'})}\n\n`);
        return res.end();
      }
      parsed.stream=true;
      res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Access-Control-Allow-Origin':'*','Connection':'keep-alive'});
      const apiReq=https.request({hostname:'api.anthropic.com',path:'/v1/messages',method:'POST',
        headers:{'Content-Type':'application/json','x-api-key':process.env.ANTHROPIC_API_KEY,'anthropic-version':'2023-06-01'}},
        apiRes=>{
          if (apiRes.statusCode !== 200) {
            let errRaw='';
            apiRes.on('data',c=>errRaw+=c);
            apiRes.on('end',()=>{
              let errMsg='Anthropic API error (status '+apiRes.statusCode+')';
              try { const e=JSON.parse(errRaw); errMsg=e.error?.message||errMsg; } catch(_){}
              res.write(`data: ${JSON.stringify({type:'error',message:errMsg})}\n\n`);
              res.end();
            });
            return;
          }
          apiRes.on('data',c=>res.write(c));
          apiRes.on('end',()=>res.end());
        });
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
        return_url: APP_URL+'/settings.html?tab=billing'
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
  if (req.method==='POST' && url==='/api/admin/delete-user') {
    const adminKey=req.headers['x-admin-secret']||'';
    if(!ADMIN_SECRET||adminKey!==ADMIN_SECRET) return json(res,401,{error:'Unauthorized'});
    try {
      const {name} = await readBody(req);
      if (!name) return json(res,400,{error:'name required'});
      const userR = await pool.query('SELECT id,name,email FROM users WHERE name ILIKE $1', [name]);
      if (userR.rows.length === 0) return json(res,404,{error:'No user found with that name'});
      const deleted = [];
      for (const u of userR.rows) {
        const uid = u.id;
        await pool.query('DELETE FROM party_answers WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM party_members WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM feed_comments WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM feed_reactions WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM feed_events WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM follows WHERE follower_id=$1 OR following_id=$1', [uid]);
        await pool.query('DELETE FROM user_badges WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM school_memberships WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM saved_questions WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM question_results WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM mock_sessions WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM sessions WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM activity WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM insights_cache WHERE user_id=$1', [uid]);
        await pool.query('DELETE FROM user_state WHERE user_id=$1', [uid]).catch(()=>{});
        await pool.query('DELETE FROM stripe_events WHERE user_id=$1', [uid]).catch(()=>{});
        await pool.query('DELETE FROM users WHERE id=$1', [uid]);
        deleted.push({id: uid, name: u.name, email: u.email});
      }
      return json(res,200,{ok:true, deleted});
    } catch(e){return json(res,500,{error:e.message});}
  }

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

  // POST /api/account/delete
  if (req.method==='POST' && url==='/api/account/delete') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      await pool.query('DELETE FROM party_answers WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM party_members WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM feed_comments WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM feed_reactions WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM feed_events WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM follows WHERE follower_id=$1 OR following_id=$1', [user.userId]);
      await pool.query('DELETE FROM user_badges WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM school_memberships WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM saved_questions WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM question_results WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM mock_sessions WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM sessions WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM activity WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM insights_cache WHERE user_id=$1', [user.userId]);
      await pool.query('DELETE FROM user_state WHERE user_id=$1', [user.userId]).catch(()=>{});
      await pool.query('DELETE FROM stripe_events WHERE user_id=$1', [user.userId]).catch(()=>{});
      await pool.query('DELETE FROM users WHERE id=$1', [user.userId]);
      return json(res,200,{ok:true});
    } catch(e){ console.error('Delete account error:', e.message); return json(res,500,{error:e.message}); }
  }

  // ── SOCIAL: FOLLOW ───────────────────────────────────────
  if (req.method==='POST' && url==='/api/social/follow') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {targetId} = await readBody(req);
      if (!targetId || targetId == user.userId) return json(res,400,{error:'Invalid target'});
      const exists = await pool.query('SELECT id FROM users WHERE id=$1', [targetId]);
      if (!exists.rows[0]) return json(res,404,{error:'User not found'});
      await pool.query(
        'INSERT INTO follows (follower_id, following_id, created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
        [user.userId, targetId, nowSec()]
      );
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/social/unfollow') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {targetId} = await readBody(req);
      await pool.query('DELETE FROM follows WHERE follower_id=$1 AND following_id=$2', [user.userId, targetId]);
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/social/profile?id=xxx — public profile (logged in only)
  if (req.method==='GET' && url==='/api/social/profile') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const targetId = params.get('id') || user.userId;
      const [userR, followerR, followingR, badgeR, schoolR, resultsR, activityR, mockR, dailyStatsR] = await Promise.all([
        pool.query('SELECT id,name,plan,created_at,avatar_data,is_private,visibility FROM users WHERE id=$1', [targetId]),
        pool.query('SELECT COUNT(*) FROM follows WHERE following_id=$1', [targetId]),
        pool.query('SELECT COUNT(*) FROM follows WHERE follower_id=$1', [targetId]),
        pool.query(`SELECT ub.badge_id, ub.awarded_at, b.name, b.icon, b.type FROM user_badges ub JOIN badges b ON b.id=ub.badge_id WHERE ub.user_id=$1 ORDER BY ub.awarded_at DESC`, [targetId]),
        pool.query(`SELECT s.name, s.conference, s.logo_url FROM school_memberships sm JOIN schools s ON s.id=sm.school_id WHERE sm.user_id=$1`, [targetId]),
        pool.query('SELECT topic,score,mastery_stage FROM question_results WHERE user_id=$1', [targetId]),
        pool.query('SELECT date, questions_answered FROM activity WHERE user_id=$1 ORDER BY date DESC LIMIT 84', [targetId]),
        pool.query('SELECT overall_score, started_at FROM mock_sessions WHERE user_id=$1 AND overall_score IS NOT NULL ORDER BY started_at DESC LIMIT 5', [targetId]),
        pool.query(`SELECT
          TO_CHAR(updated_at::timestamp, 'YYYY-MM-DD') as date,
          ROUND(AVG(score))::INT as avg_score,
          MAX(score) as best_score,
          topic,
          COUNT(*) as topic_count
        FROM question_results
        WHERE user_id=$1 AND score IS NOT NULL
        GROUP BY TO_CHAR(updated_at::timestamp, 'YYYY-MM-DD'), topic
        ORDER BY date DESC, topic_count DESC`, [targetId]),
      ]);
      if (!userR.rows[0]) return json(res,404,{error:'User not found'});
      const u = userR.rows[0];
      const all = resultsR.rows;
      const overall = all.length > 0 ? Math.round(all.reduce((s,r)=>s+r.score,0)/all.length) : null;
      const byTopic = {};
      all.forEach(r => {
        if (!byTopic[r.topic]) byTopic[r.topic] = { scores:[], stages:{} };
        byTopic[r.topic].scores.push(r.score);
        byTopic[r.topic].stages[r.mastery_stage] = (byTopic[r.topic].stages[r.mastery_stage]||0)+1;
      });
      const topicBreakdown = Object.entries(byTopic).map(([topic, d]) => {
        const avg = Math.round(d.scores.reduce((a,b)=>a+b,0)/d.scores.length);
        const dominantStage = Object.entries(d.stages).sort((a,b)=>b[1]-a[1])[0]?.[0] || 'new';
        return { topic, avg, count: d.scores.length, stage: dominantStage };
      }).sort((a,b) => b.avg - a.avg);
      const actDates = new Set(activityR.rows.map(a=>a.date));
      const activityMap = Object.fromEntries(activityR.rows.map(a=>[a.date, a.questions_answered||0]));
      // Build per-day rich stats from dailyStatsR
      const dailyStats = {};
      for (const row of dailyStatsR.rows) {
        if (!dailyStats[row.date]) {
          dailyStats[row.date] = { avgScore: row.avg_score, bestScore: row.best_score, topTopic: row.topic, topTopicCount: parseInt(row.topic_count) };
        }
        // first row per date is top topic (ORDER BY topic_count DESC)
      }
      let streak = 0;
      for (let i=0;i<365;i++) {
        const d=new Date(); d.setDate(d.getDate()-i);
        const ds=d.toISOString().slice(0,10);
        if (actDates.has(ds)) streak++; else if (i>0) break;
      }
      const masteredCount = all.filter(r=>r.mastery_stage==='mastered').length;
      const strugglingCount = all.filter(r=>r.mastery_stage==='struggling').length;
      const isFollowingR = await pool.query('SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2', [user.userId, targetId]);
      const isFollowing = isFollowingR.rows.length > 0;
      const isMutual = isFollowing && (await pool.query('SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2', [targetId, user.userId])).rows.length > 0;
      const isMe = String(user.userId) === String(targetId);

      // Privacy check
      const isPrivate = !!u.is_private;
      const visibility = u.visibility || 'public';
      // NULL values from pre-privacy users = public
      const effectivelyPublic = !u.is_private && (!u.visibility || u.visibility === 'public');
      const userSchoolR = !isMe ? await pool.query('SELECT school_id FROM school_memberships WHERE user_id=$1', [user.userId]) : null;
      const viewerSchoolId = userSchoolR?.rows[0]?.school_id;
      const targetSchoolId = schoolR.rows[0]?.id;

      let canViewFull = isMe;
      if (!canViewFull) {
        if (effectivelyPublic || visibility === 'public') {
          canViewFull = true;
        } else if (isPrivate) {
          canViewFull = isFollowing;
        } else if (visibility === 'public') {
          canViewFull = true;
        } else if (visibility === 'friends') {
          canViewFull = isMutual;
        } else if (visibility === 'school') {
          canViewFull = viewerSchoolId && targetSchoolId && String(viewerSchoolId) === String(targetSchoolId);
        } else if (visibility === 'school_and_friends') {
          const sameSchool = viewerSchoolId && targetSchoolId && String(viewerSchoolId) === String(targetSchoolId);
          canViewFull = sameSchool || isMutual;
        }
      }

      // Recommended profiles (shown when account is private/locked)
      let recommended = [];
      if (!canViewFull && !isMe) {
        const recR = await pool.query(
          `SELECT u2.id, u2.name, u2.plan, s.name as school_name, s.conference,
                  (SELECT COUNT(*) FROM follows WHERE following_id=u2.id) as followers
           FROM users u2
           LEFT JOIN school_memberships sm2 ON sm2.user_id=u2.id
           LEFT JOIN schools s ON s.id=sm2.school_id
           WHERE u2.id != $1 AND u2.id != $2 AND (u2.is_private IS NULL OR u2.is_private=0)
           ORDER BY RANDOM() LIMIT 6`,
          [targetId, user.userId]
        );
        recommended = recR.rows;
      }

      return json(res,200,{
        id: u.id, name: u.name, plan: u.plan, memberSince: u.created_at, avatarData: u.avatar_data || null,
        followers: parseInt(followerR.rows[0].count),
        following: parseInt(followingR.rows[0].count),
        isFollowing,
        isPrivate,
        visibility,
        canViewFull,
        badges: canViewFull ? badgeR.rows : [],
        school: schoolR.rows[0] || null,
        activityDates: canViewFull ? [...actDates] : [],
        activityMap: canViewFull ? activityMap : {},
        dailyStats: canViewFull ? dailyStats : {},
        recentMocks: canViewFull ? mockR.rows : [],
        stats: {
          overall: canViewFull ? overall : null,
          totalAnswered: all.length,
          streak,
          masteredCount: canViewFull ? masteredCount : null,
          strugglingCount: canViewFull ? strugglingCount : null,
        },
        topicBreakdown: canViewFull ? topicBreakdown : [],
        recommended,
      });
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/progress/difficulty — per-topic difficulty unlock status
  if (req.method==='GET' && url==='/api/progress/difficulty') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const histR = await pool.query(
        'SELECT question_id, score, mastery_stage FROM question_results WHERE user_id=$1',
        [user.userId]
      );
      const seenMap = {};
      histR.rows.forEach(r => { seenMap[r.question_id] = r; });

      const allIds = Object.keys(QUESTIONS_BY_ID);
      const allTopics = [...new Set(allIds.map(id => QUESTIONS_BY_ID[id].topic))];
      const DIFF_ORDER = ['basic','intermediate','hard'];

      const result = {};
      allTopics.forEach(t => {
        const topicQs = allIds.filter(id => QUESTIONS_BY_ID[id].topic === t);
        const byDiff = {};
        DIFF_ORDER.forEach(d => {
          const ids = topicQs.filter(id => QUESTIONS_BY_ID[id].difficulty === d);
          const seen = ids.filter(id => seenMap[id]);
          const scores = seen.map(id => seenMap[id].score).filter(s=>s!=null);
          byDiff[d] = {
            total: ids.length,
            seen: seen.length,
            avgScore: scores.length > 0 ? Math.round(scores.reduce((a,b)=>a+b,0)/scores.length) : null,
            seenRatio: ids.length > 0 ? seen.length/ids.length : 0,
          };
        });

        // Compute unlocked levels
        const unlocked = ['basic'];
        if (byDiff.basic.seen > 0 && (byDiff.basic.avgScore >= 70 || byDiff.basic.seenRatio >= 0.6)) {
          unlocked.push('intermediate');
        }
        if (unlocked.includes('intermediate') && byDiff.intermediate.seen > 0 &&
            (byDiff.intermediate.avgScore >= 75 || byDiff.intermediate.seenRatio >= 0.6)) {
          unlocked.push('hard');
        }

        result[t] = { byDiff, unlocked, currentLevel: unlocked[unlocked.length-1] };
      });
      return json(res,200,{ topics: result });
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/social/answers?id=xxx&topic=xxx&limit=xxx&offset=xxx
  if (req.method==='GET' && url==='/api/social/answers') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const targetId = params.get('id') || user.userId;
      // Privacy check
      if (String(targetId) !== String(user.userId)) {
        const privR = await pool.query('SELECT is_private, visibility FROM users WHERE id=$1', [targetId]);
        const pv = privR.rows[0] || {};
        if (pv.is_private || pv.visibility !== 'public') {
          const isFollowing = await pool.query('SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2', [user.userId, targetId]);
          if (isFollowing.rows.length === 0) return json(res,403,{error:'This account is private.'});
        }
      }
      const topic = params.get('topic') || null;
      const limit = Math.min(parseInt(params.get('limit'))||20, 50);
      const offset = parseInt(params.get('offset'))||0;
      const topicFilter = topic && topic !== 'All' ? 'AND qr.topic=$3' : '';
      const vals = topic && topic !== 'All' ? [targetId, limit, topic, offset] : [targetId, limit, offset];
      const r = await pool.query(
        `SELECT qr.question_id, qr.topic, qr.score, qr.mastery_stage, qr.attempt_count, qr.updated_at,
                (SELECT COUNT(*) FROM sessions s WHERE s.user_id=$1 AND s.question_id=qr.question_id) as times_seen
         FROM question_results qr
         WHERE qr.user_id=$1 ${topicFilter}
         ORDER BY qr.updated_at DESC
         LIMIT $2 OFFSET $${topic && topic !== 'All' ? 4 : 3}`,
        vals
      );
      const total = await pool.query(
        `SELECT COUNT(*) FROM question_results WHERE user_id=$1 ${topicFilter}`,
        topic && topic !== 'All' ? [targetId, topic] : [targetId]
      );
      const rows = r.rows.map(row => {
        const q = QUESTIONS_BY_ID[row.question_id];
        return {
          questionId: row.question_id,
          question: q?.question || '(Question not found)',
          modelAnswer: q?.model_answer || '',
          topic: row.topic,
          score: row.score,
          masteryStage: row.mastery_stage,
          attemptCount: parseInt(row.attempt_count),
          timesSeen: parseInt(row.times_seen),
          updatedAt: row.updated_at,
        };
      });
      return json(res,200,{ answers: rows, total: parseInt(total.rows[0].count), limit, offset });
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/social/browse?school=1  — all users (optionally filtered to same school)
  if (req.method==='GET' && url==='/api/social/browse') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const schoolOnly = params.get('school') === '1';
      let q, vals;
      if (schoolOnly) {
        q = `SELECT u.id, u.name, u.plan, s.name as school_name, s.conference,
               (SELECT COUNT(*) FROM follows WHERE following_id=u.id) as followers,
               (SELECT COUNT(*) FROM follows WHERE follower_id=u.id) as following
             FROM users u
             JOIN school_memberships sm ON sm.user_id=u.id
             JOIN schools s ON s.id=sm.school_id
             WHERE s.id = (SELECT school_id FROM school_memberships WHERE user_id=$1) AND u.id != $1
             ORDER BY u.created_at DESC LIMIT 50`;
        vals = [user.userId];
      } else {
        q = `SELECT u.id, u.name, u.plan, s.name as school_name, s.conference,
               (SELECT COUNT(*) FROM follows WHERE following_id=u.id) as followers,
               (SELECT COUNT(*) FROM follows WHERE follower_id=u.id) as following
             FROM users u
             LEFT JOIN school_memberships sm ON sm.user_id=u.id
             LEFT JOIN schools s ON s.id=sm.school_id
             WHERE u.id != $1
             ORDER BY u.created_at DESC LIMIT 50`;
        vals = [user.userId];
      }
      const r = await pool.query(q, vals);
      const followingMe = await pool.query('SELECT following_id FROM follows WHERE follower_id=$1', [user.userId]);
      const followingSet = new Set(followingMe.rows.map(r=>String(r.following_id)));
      return json(res,200,{users: r.rows.map(u=>({...u, isFollowing: followingSet.has(String(u.id))}))});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/social/search?q=name
  if (req.method==='GET' && url==='/api/social/search') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const q = (params.get('q')||'').trim();
      if (!q || q.length < 2) return json(res,400,{error:'Query too short'});
      const r = await pool.query(
        `SELECT u.id, u.name, u.plan, s.name as school_name, s.conference
         FROM users u
         LEFT JOIN school_memberships sm ON sm.user_id=u.id
         LEFT JOIN schools s ON s.id=sm.school_id
         WHERE u.name ILIKE $1 AND u.id != $2 LIMIT 20`,
        [`%${q}%`, user.userId]
      );
      const following = await pool.query('SELECT following_id FROM follows WHERE follower_id=$1', [user.userId]);
      const followingSet = new Set(following.rows.map(r=>String(r.following_id)));
      return json(res,200,{users: r.rows.map(u=>({...u, isFollowing: followingSet.has(String(u.id))}))});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/social/feed
  if (req.method==='GET' && url==='/api/social/feed') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const limit = Math.min(parseInt(params.get('limit'))||30, 50);
      const before = parseInt(params.get('before')) || null;
      const tab = params.get('tab') || 'following';
      let whereClause;
      if (tab === 'mine') {
        whereClause = `fe.user_id=$1`;
      } else if (tab === 'school') {
        whereClause = `fe.user_id IN (SELECT sm2.user_id FROM school_memberships sm2 WHERE sm2.school_id = (SELECT school_id FROM school_memberships WHERE user_id=$1))`;
      } else {
        whereClause = `(fe.user_id=$1 OR fe.user_id IN (SELECT following_id FROM follows WHERE follower_id=$1))`;
      }
      const r = await pool.query(
        `SELECT fe.id, fe.user_id, fe.type, fe.payload, fe.created_at,
                u.name as user_name, u.plan as user_plan
         FROM feed_events fe
         JOIN users u ON u.id=fe.user_id
         WHERE ${whereClause} ${before ? 'AND fe.created_at < $3' : ''}
         ORDER BY fe.created_at DESC LIMIT $2`,
        before ? [user.userId, limit, before] : [user.userId, limit]
      );
      // Attach reaction + comment counts
      const eventIds = r.rows.map(e=>e.id);
      let reactionMap = {}, commentMap = {};
      if (eventIds.length > 0) {
        const [rxR, cmR] = await Promise.all([
          pool.query(`SELECT event_id, emoji, COUNT(*) FROM feed_reactions WHERE event_id=ANY($1) GROUP BY event_id, emoji`, [eventIds]),
          pool.query(`SELECT event_id, COUNT(*) FROM feed_comments WHERE event_id=ANY($1) GROUP BY event_id`, [eventIds]),
        ]);
        rxR.rows.forEach(r => {
          if (!reactionMap[r.event_id]) reactionMap[r.event_id] = {};
          reactionMap[r.event_id][r.emoji] = parseInt(r.count);
        });
        cmR.rows.forEach(r => { commentMap[r.event_id] = parseInt(r.count); });
        // My reactions
        const myRx = await pool.query(`SELECT event_id, emoji FROM feed_reactions WHERE user_id=$1 AND event_id=ANY($2)`, [user.userId, eventIds]);
        myRx.rows.forEach(r => {
          if (!reactionMap[r.event_id]) reactionMap[r.event_id] = {};
          reactionMap[r.event_id]['_mine_'+r.emoji] = true;
        });
      }
      const events = r.rows.map(e=>({
        ...e,
        reactions: reactionMap[e.id]||{},
        commentCount: commentMap[e.id]||0,
      }));
      return json(res,200,{events});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/social/react
  if (req.method==='POST' && url==='/api/social/react') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {eventId, emoji} = await readBody(req);
      if (!eventId || !emoji) return json(res,400,{error:'eventId and emoji required'});
      const allowed = ['🔥','👏','💪','🎯','😮'];
      if (!allowed.includes(emoji)) return json(res,400,{error:'Invalid emoji'});
      await pool.query(
        'INSERT INTO feed_reactions (event_id, user_id, emoji, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',
        [eventId, user.userId, emoji, nowSec()]
      );
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  if (req.method==='POST' && url==='/api/social/unreact') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {eventId, emoji} = await readBody(req);
      await pool.query('DELETE FROM feed_reactions WHERE event_id=$1 AND user_id=$2 AND emoji=$3', [eventId, user.userId, emoji]);
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/social/comments?eventId=xxx
  if (req.method==='GET' && url==='/api/social/comments') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const eventId = params.get('eventId');
      if (!eventId) return json(res,400,{error:'eventId required'});
      const r = await pool.query(
        `SELECT fc.id, fc.body, fc.created_at, u.id as user_id, u.name as user_name
         FROM feed_comments fc JOIN users u ON u.id=fc.user_id
         WHERE fc.event_id=$1 ORDER BY fc.created_at ASC`,
        [eventId]
      );
      return json(res,200,{comments: r.rows});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/social/comment
  if (req.method==='POST' && url==='/api/social/comment') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {eventId, body} = await readBody(req);
      if (!eventId || !body || !body.trim()) return json(res,400,{error:'eventId and body required'});
      const trimmed = body.trim().slice(0, 500);
      const r = await pool.query(
        'INSERT INTO feed_comments (event_id, user_id, body, created_at) VALUES ($1,$2,$3,$4) RETURNING id',
        [eventId, user.userId, trimmed, nowSec()]
      );
      return json(res,200,{ok:true, id: r.rows[0].id});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/social/followers?id=xxx  /  GET /api/social/following?id=xxx
  if (req.method==='GET' && (url==='/api/social/followers' || url==='/api/social/following')) {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const targetId = params.get('id') || user.userId;
      const isFollowers = url==='/api/social/followers';
      const r = await pool.query(
        isFollowers
          ? `SELECT u.id, u.name, u.plan,
               s.name as school_name, s.conference, s.logo_url,
               (SELECT COUNT(*) FROM follows WHERE following_id=u.id) as followers,
               (SELECT COUNT(*) FROM follows WHERE follower_id=u.id) as following
             FROM follows f JOIN users u ON u.id=f.follower_id
             LEFT JOIN school_memberships sm ON sm.user_id=u.id
             LEFT JOIN schools s ON s.id=sm.school_id
             WHERE f.following_id=$1 ORDER BY f.created_at DESC`
          : `SELECT u.id, u.name, u.plan,
               s.name as school_name, s.conference, s.logo_url,
               (SELECT COUNT(*) FROM follows WHERE following_id=u.id) as followers,
               (SELECT COUNT(*) FROM follows WHERE follower_id=u.id) as following
             FROM follows f JOIN users u ON u.id=f.following_id
             LEFT JOIN school_memberships sm ON sm.user_id=u.id
             LEFT JOIN schools s ON s.id=sm.school_id
             WHERE f.follower_id=$1 ORDER BY f.created_at DESC`,
        [targetId]
      );
      const myFollowing = await pool.query('SELECT following_id FROM follows WHERE follower_id=$1', [user.userId]);
      const mySet = new Set(myFollowing.rows.map(r=>String(r.following_id)));
      return json(res,200,{users: r.rows.map(u=>({...u, isFollowing: mySet.has(String(u.id))}))});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // ── SCHOOL / CONFERENCE ──────────────────────────────────
  // GET /api/school/me
  if (req.method==='GET' && url==='/api/school/me') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const r = await pool.query(
        `SELECT s.id, s.name, s.conference, s.logo_url FROM school_memberships sm
         JOIN schools s ON s.id=sm.school_id WHERE sm.user_id=$1`,
        [user.userId]
      );
      return json(res,200,{school: r.rows[0]||null});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/school/leaderboard?conference=NESCAC
  if (req.method==='GET' && url==='/api/school/leaderboard') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const conference = params.get('conference');
      const r = await pool.query(
        `SELECT s.id, s.name, s.conference,
                COUNT(DISTINCT sm.user_id) as members,
                COALESCE(AVG(qr.score),0)::INT as avg_score,
                COUNT(qr.score) as total_answers
         FROM schools s
         LEFT JOIN school_memberships sm ON sm.school_id=s.id
         LEFT JOIN question_results qr ON qr.user_id=sm.user_id
         ${conference ? 'WHERE s.conference=$1' : ''}
         GROUP BY s.id ORDER BY avg_score DESC LIMIT 50`,
        conference ? [conference] : []
      );
      return json(res,200,{schools: r.rows});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/school/conferences
  if (req.method==='GET' && url==='/api/school/conferences') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const r = await pool.query('SELECT DISTINCT conference FROM schools ORDER BY conference');
      return json(res,200,{conferences: r.rows.map(r=>r.conference)});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/school/challenges
  if (req.method==='GET' && url==='/api/school/challenges') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const schoolR = await pool.query(
        `SELECT s.conference FROM school_memberships sm JOIN schools s ON s.id=sm.school_id WHERE sm.user_id=$1`,
        [user.userId]
      );
      const conference = schoolR.rows[0]?.conference;
      if (!conference) return json(res,200,{challenges:[], enrolled: false});
      const r = await pool.query(
        `SELECT cc.*, cs.total_score, cs.participants,
                ROW_NUMBER() OVER (PARTITION BY cc.id ORDER BY cs.total_score DESC) as rank
         FROM conference_challenges cc
         LEFT JOIN challenge_scores cs ON cs.challenge_id=cc.id
         LEFT JOIN school_memberships sm2 ON sm2.school_id=cs.school_id AND sm2.user_id=$1
         WHERE cc.conference=$2 ORDER BY cc.starts_at DESC`,
        [user.userId, conference]
      );
      return json(res,200,{challenges: r.rows, conference, enrolled: true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/admin/challenge — create a conference challenge (admin only)
  if (req.method==='POST' && url==='/api/admin/challenge') {
    const adminKey=req.headers['x-admin-secret']||'';
    if(!ADMIN_SECRET||adminKey!==ADMIN_SECRET) return json(res,401,{error:'Unauthorized'});
    try {
      const {conference, title, starts_at, ends_at} = await readBody(req);
      if (!conference||!title||!starts_at||!ends_at) return json(res,400,{error:'conference, title, starts_at, ends_at required'});
      const r = await pool.query(
        'INSERT INTO conference_challenges (conference,title,starts_at,ends_at,status) VALUES ($1,$2,$3,$4,$5) RETURNING id',
        [conference, title, starts_at, ends_at, 'upcoming']
      );
      return json(res,200,{ok:true, id: r.rows[0].id});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/admin/badge — create a badge definition (admin only)
  if (req.method==='POST' && url==='/api/admin/badge') {
    const adminKey=req.headers['x-admin-secret']||'';
    if(!ADMIN_SECRET||adminKey!==ADMIN_SECRET) return json(res,401,{error:'Unauthorized'});
    try {
      const {id, name, description, icon, type} = await readBody(req);
      if (!id||!name) return json(res,400,{error:'id and name required'});
      await pool.query(
        'INSERT INTO badges (id,name,description,icon,type) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO UPDATE SET name=$2,description=$3,icon=$4,type=$5',
        [id, name, description||'', icon||'🏅', type||'general']
      );
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // ── STUDY PARTIES ────────────────────────────────────────
  // POST /api/party/create
  if (req.method==='POST' && url==='/api/party/create') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const planR = await pool.query('SELECT plan FROM users WHERE id=$1', [user.userId]);
      const plan = planR.rows[0]?.plan || 'free';
      if (plan === 'free') {
        return json(res,402,{error:'upgrade_required', message:'Hosting a study party requires Pro or Recruiting Pass. Free users can join parties — upgrade to host your own.'});
      }
      if (plan === 'monthly') {
        const since = nowSec() - ONE_DAY;
        const recentHost = await pool.query(
          `SELECT COUNT(*) FROM study_parties WHERE host_id=$1 AND started_at IS NOT NULL AND started_at >= $2`,
          [user.userId, since]
        );
        if (parseInt(recentHost.rows[0].count) >= 1) {
          return json(res,402,{error:'host_limit', message:'Pro includes 1 hosted study party per 24 hours. Upgrade to Recruiting Pass for unlimited hosting.'});
        }
      }
      const {topic, timeLimitSec} = await readBody(req);
      let code;
      for (let i=0; i<10; i++) {
        code = generatePartyCode();
        const exists = await pool.query('SELECT id FROM study_parties WHERE id=$1', [code]);
        if (!exists.rows[0]) break;
      }
      const tl = (parseInt(timeLimitSec)||0) > 0 ? parseInt(timeLimitSec) : null;
      await pool.query('INSERT INTO study_parties (id,host_id,status,topic,time_limit_sec,created_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [code, user.userId, 'lobby', topic||null, tl, nowSec()]);
      await pool.query('INSERT INTO party_members (party_id,user_id,joined_at,status) VALUES ($1,$2,$3,$4)',
        [code, user.userId, nowSec(), 'active']);
      return json(res,200,{ok:true, code});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/party/join
  if (req.method==='POST' && url==='/api/party/join') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const planR = await pool.query('SELECT plan FROM users WHERE id=$1', [user.userId]);
      const plan = planR.rows[0]?.plan || 'free';
      if (plan === 'free') {
        const since = nowSec() - ONE_DAY;
        const recentJoins = await pool.query(
          `SELECT COUNT(*) FROM party_members pm JOIN study_parties sp ON sp.id=pm.party_id
           WHERE pm.user_id=$1 AND sp.started_at IS NOT NULL AND sp.started_at >= $2`,
          [user.userId, since]
        );
        if (parseInt(recentJoins.rows[0].count) >= 1) {
          return json(res,402,{error:'join_limit', message:'Free accounts include 1 study party session per 24 hours. Upgrade to Pro for unlimited sessions.'});
        }
      }
      const {code} = await readBody(req);
      if (!code) return json(res,400,{error:'code required'});
      const partyR = await pool.query('SELECT * FROM study_parties WHERE id=$1', [code]);
      if (!partyR.rows[0]) return json(res,404,{error:'Party not found'});
      const party = partyR.rows[0];
      if (party.status === 'complete') return json(res,400,{error:'This party has already ended'});
      if (party.status === 'active') return json(res,400,{error:'Session already in progress'});
      await pool.query('INSERT INTO party_members (party_id,user_id,joined_at,status) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',
        [code, user.userId, nowSec(), 'active']);
      const membersR = await pool.query(
        `SELECT pm.user_id, u.name FROM party_members pm JOIN users u ON u.id=pm.user_id WHERE pm.party_id=$1 AND pm.status='active'`, [code]);
      return json(res,200,{ok:true, party: {id:party.id, topic:party.topic, timeLimitSec:party.time_limit_sec, status:party.status, hostId:party.host_id}, members: membersR.rows});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/party/state?code=xxx
  if (req.method==='GET' && url==='/api/party/state') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const code = params.get('code');
      if (!code) return json(res,400,{error:'code required'});
      const [partyR, membersR] = await Promise.all([
        pool.query('SELECT * FROM study_parties WHERE id=$1', [code]),
        pool.query(`SELECT pm.user_id, u.name, pm.status FROM party_members pm
                    JOIN users u ON u.id=pm.user_id WHERE pm.party_id=$1`, [code]),
      ]);
      if (!partyR.rows[0]) return json(res,404,{error:'Party not found'});
      const party = partyR.rows[0];
      const currentQId = party.question_ids ? party.question_ids[party.current_question_index] : null;
      const currentQ = currentQId ? QUESTIONS_BY_ID[currentQId] : null;
      // Who has answered this question already
      let answered = [];
      if (currentQId) {
        const ansR = await pool.query(
          `SELECT user_id FROM party_answers WHERE party_id=$1 AND question_id=$2`,
          [code, currentQId]
        );
        answered = ansR.rows.map(r=>r.user_id);
      }
      return json(res,200,{
        party: {
          id: party.id, hostId: party.host_id, status: party.status,
          topic: party.topic, timeLimitSec: party.time_limit_sec,
          currentQuestionIndex: party.current_question_index,
          totalQuestions: party.question_ids ? party.question_ids.length : 0,
        },
        currentQuestion: currentQ ? {id:currentQId, question:currentQ.question, topic:currentQ.topic} : null,
        members: membersR.rows,
        answeredUserIds: answered,
      });
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/party/start — host only, picks questions and starts session
  if (req.method==='POST' && url==='/api/party/start') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {code, questionCount} = await readBody(req);
      if (!code) return json(res,400,{error:'code required'});
      const partyR = await pool.query('SELECT * FROM study_parties WHERE id=$1', [code]);
      if (!partyR.rows[0]) return json(res,404,{error:'Party not found'});
      const party = partyR.rows[0];
      if (party.host_id != user.userId) return json(res,403,{error:'Only the host can start'});
      if (party.status !== 'lobby') return json(res,400,{error:'Party already started'});
      const n = Math.min(parseInt(questionCount)||10, 30);
      const topic = party.topic;
      let eligibleIds;
      if (topic && topic !== 'All') {
        // Support comma-joined multi-topic e.g. "Accounting,DCF,LBO"
        const topics = topic.split(',').map(t => t.trim()).filter(Boolean);
        eligibleIds = Object.keys(QUESTIONS_BY_ID).filter(id => topics.includes(QUESTIONS_BY_ID[id].topic));
      } else {
        eligibleIds = Object.keys(QUESTIONS_BY_ID);
      }
      const questionIds = shuffle(eligibleIds).slice(0, n);
      await pool.query(
        `UPDATE study_parties SET status='active', question_ids=$1, current_question_index=0, started_at=$2 WHERE id=$3`,
        [JSON.stringify(questionIds), nowSec(), code]
      );
      const firstQ = QUESTIONS_BY_ID[questionIds[0]];
      broadcastToParty(code, {
        type: 'party_started',
        currentQuestionIndex: 0,
        totalQuestions: questionIds.length,
        question: { id: questionIds[0], question: firstQ?.question, topic: firstQ?.topic },
      });
      return json(res,200,{ok:true, totalQuestions: questionIds.length});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/party/answer — submit answer for current question
  if (req.method==='POST' && url==='/api/party/answer') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {code, questionId, answerText} = await readBody(req);
      if (!code||!questionId) return json(res,400,{error:'code and questionId required'});
      const partyR = await pool.query('SELECT * FROM study_parties WHERE id=$1', [code]);
      if (!partyR.rows[0]) return json(res,404,{error:'Party not found'});
      const party = partyR.rows[0];
      if (party.status !== 'active') return json(res,400,{error:'Party not active'});
      // Verify this is the current question
      const currentQId = party.question_ids[party.current_question_index];
      if (currentQId !== questionId) return json(res,400,{error:'Not the current question'});
      // Save answer (ungraded for now)
      await pool.query(
        `INSERT INTO party_answers (party_id,user_id,question_id,answer_text,submitted_at)
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT (party_id,user_id,question_id) DO UPDATE SET answer_text=$4, submitted_at=$5`,
        [code, user.userId, questionId, answerText||'', nowSec()]
      );
      // Broadcast to party that this user answered (no answer text revealed)
      broadcastToParty(code, { type: 'member_answered', userId: user.userId });
      // Check if all active members have answered
      const activeMembers = await pool.query(
        `SELECT user_id FROM party_members WHERE party_id=$1 AND status='active'`, [code]
      );
      const answered = await pool.query(
        `SELECT user_id FROM party_answers WHERE party_id=$1 AND question_id=$2`, [code, questionId]
      );
      const allAnswered = answered.rows.length >= activeMembers.rows.length;
      if (allAnswered) {
        // Grade all answers — requires host to be on a paid plan
        const hostPlanR = await pool.query('SELECT plan FROM users WHERE id=(SELECT host_id FROM study_parties WHERE id=$1)', [code]);
        const hostPlan = hostPlanR.rows[0]?.plan || 'free';
        const q = QUESTIONS_BY_ID[questionId];
        if (hostPlan === 'free') {
          // Show answers side-by-side without AI grading for free hosts
          const allAnswersR = await pool.query(
            `SELECT pa.user_id, pa.answer_text, u.name FROM party_answers pa JOIN users u ON u.id=pa.user_id
             WHERE pa.party_id=$1 AND pa.question_id=$2`, [code, questionId]
          );
          broadcastToParty(code, {
            type: 'question_graded',
            questionId,
            question: { id: questionId, question: q?.question, model_answer: q?.model_answer, topic: q?.topic },
            results: allAnswersR.rows.map(r=>({ userId: r.user_id, name: r.name, answerText: r.answer_text, score: null, grade: { verdict: 'Upgrade to Pro to unlock AI grading in study parties.', strengths:'', gaps:'' } })),
            ungradedFree: true,
          });
        } else {
          const gradePromises = answered.rows.map(async ({user_id}) => {
            const ansR = await pool.query(
              'SELECT answer_text FROM party_answers WHERE party_id=$1 AND user_id=$2 AND question_id=$3',
              [code, user_id, questionId]
            );
            const grade = await gradeMockAnswer(q, ansR.rows[0]?.answer_text||'');
            await pool.query(
              `UPDATE party_answers SET score=$1, grade_payload=$2 WHERE party_id=$3 AND user_id=$4 AND question_id=$5`,
              [grade.score, JSON.stringify(grade), code, user_id, questionId]
            );
            return { userId: user_id, score: grade.score, verdict: grade.verdict, grade };
          });
          const results = await Promise.all(gradePromises);
          const allAnswersR = await pool.query(
            `SELECT pa.user_id, pa.answer_text, pa.score, pa.grade_payload, u.name
             FROM party_answers pa JOIN users u ON u.id=pa.user_id
             WHERE pa.party_id=$1 AND pa.question_id=$2`,
            [code, questionId]
          );
          broadcastToParty(code, {
            type: 'question_graded',
            questionId,
            question: { id: questionId, question: q?.question, model_answer: q?.model_answer, topic: q?.topic },
            results: allAnswersR.rows.map(r=>({
              userId: r.user_id, name: r.name, answerText: r.answer_text,
              score: r.score, grade: r.grade_payload,
            })),
          });
        }
      }
      return json(res,200,{ok:true, allAnswered});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/party/next — host advances to next question
  if (req.method==='POST' && url==='/api/party/next') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {code} = await readBody(req);
      if (!code) return json(res,400,{error:'code required'});
      const partyR = await pool.query('SELECT * FROM study_parties WHERE id=$1', [code]);
      if (!partyR.rows[0]) return json(res,404,{error:'Party not found'});
      const party = partyR.rows[0];
      if (party.host_id != user.userId) return json(res,403,{error:'Only the host can advance'});
      if (party.status !== 'active') return json(res,400,{error:'Party not active'});
      const nextIndex = party.current_question_index + 1;
      if (nextIndex >= party.question_ids.length) {
        // Session complete
        await pool.query(`UPDATE study_parties SET status='complete', completed_at=$1 WHERE id=$2`, [nowSec(), code]);
        // Compute final scores per member
        const finalR = await pool.query(
          `SELECT pa.user_id, u.name, AVG(pa.score)::INT as avg_score, COUNT(pa.question_id) as answered
           FROM party_answers pa JOIN users u ON u.id=pa.user_id
           WHERE pa.party_id=$1 GROUP BY pa.user_id, u.name ORDER BY avg_score DESC`,
          [code]
        );
        broadcastToParty(code, { type: 'party_complete', finalScores: finalR.rows });
        // Emit feed event for all participants
        for (const member of finalR.rows) {
          await emitFeedEvent(member.user_id, 'party_complete', {
            partyId: code,
            avgScore: member.avg_score,
            participants: finalR.rows.length,
          });
        }
        return json(res,200,{ok:true, complete:true});
      }
      await pool.query('UPDATE study_parties SET current_question_index=$1 WHERE id=$2', [nextIndex, code]);
      const nextQId = party.question_ids[nextIndex];
      const nextQ = QUESTIONS_BY_ID[nextQId];
      broadcastToParty(code, {
        type: 'next_question',
        currentQuestionIndex: nextIndex,
        totalQuestions: party.question_ids.length,
        question: { id: nextQId, question: nextQ?.question, topic: nextQ?.topic },
      });
      return json(res,200,{ok:true, complete:false, nextIndex});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/party/skip — host skips a member (submits blank)
  if (req.method==='POST' && url==='/api/party/skip') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const {code, targetUserId} = await readBody(req);
      if (!code||!targetUserId) return json(res,400,{error:'code and targetUserId required'});
      const partyR = await pool.query('SELECT * FROM study_parties WHERE id=$1', [code]);
      if (!partyR.rows[0]) return json(res,404,{error:'Party not found'});
      const party = partyR.rows[0];
      if (party.host_id != user.userId) return json(res,403,{error:'Only the host can skip members'});
      const currentQId = party.question_ids[party.current_question_index];
      await pool.query(
        `INSERT INTO party_answers (party_id,user_id,question_id,answer_text,score,grade_payload,submitted_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (party_id,user_id,question_id) DO NOTHING`,
        [code, targetUserId, currentQId, '', 0, JSON.stringify({score:0,verdict:'Skipped',strengths:'',gaps:'No answer submitted.',concept_gap:null}), nowSec()]
      );
      broadcastToParty(code, { type: 'member_answered', userId: targetUserId });
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/party/results?code=xxx — full results for completed party
  if (req.method==='GET' && url==='/api/party/results') {
    const user=getUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    try {
      const params = new URLSearchParams(req.url.split('?')[1]||'');
      const code = params.get('code');
      if (!code) return json(res,400,{error:'code required'});
      const partyR = await pool.query('SELECT * FROM study_parties WHERE id=$1', [code]);
      if (!partyR.rows[0]) return json(res,404,{error:'Party not found'});
      const party = partyR.rows[0];
      const answersR = await pool.query(
        `SELECT pa.user_id, pa.question_id, pa.answer_text, pa.score, pa.grade_payload, u.name
         FROM party_answers pa JOIN users u ON u.id=pa.user_id WHERE pa.party_id=$1`,
        [code]
      );
      // Group by question
      const byQuestion = {};
      for (const row of answersR.rows) {
        if (!byQuestion[row.question_id]) {
          const q = QUESTIONS_BY_ID[row.question_id];
          byQuestion[row.question_id] = { question: q?.question, topic: q?.topic, modelAnswer: q?.model_answer, answers: [] };
        }
        byQuestion[row.question_id].answers.push({
          userId: row.user_id, name: row.name,
          answerText: row.answer_text, score: row.score, grade: row.grade_payload,
        });
      }
      // Final leaderboard
      const leaderboard = {};
      for (const row of answersR.rows) {
        if (!leaderboard[row.user_id]) leaderboard[row.user_id] = { userId:row.user_id, name:row.name, scores:[], total:0 };
        if (row.score != null) leaderboard[row.user_id].scores.push(row.score);
      }
      const finalScores = Object.values(leaderboard).map(m=>({
        ...m,
        avgScore: m.scores.length > 0 ? Math.round(m.scores.reduce((a,b)=>a+b,0)/m.scores.length) : 0,
      })).sort((a,b)=>b.avgScore-a.avgScore);
      return json(res,200,{
        partyId: code, topic: party.topic, completedAt: party.completed_at,
        questions: party.question_ids || [],
        byQuestion, finalScores,
      });
    } catch(e){return json(res,500,{error:e.message});}
  }

  // GET /api/admin/reports
  if (req.method==='GET' && url.startsWith('/api/admin/reports')) {
    if (req.headers['x-admin-secret'] !== process.env.ADMIN_SECRET) return json(res,401,{error:'Unauthorized'});
    try {
      const r = await pool.query(
        `SELECT br.*, u.email, u.name FROM bug_reports br
         LEFT JOIN users u ON u.id=br.user_id
         ORDER BY br.created_at DESC LIMIT 100`
      );
      return json(res,200,{reports: r.rows});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // POST /api/report — bug / feedback submission
  if (req.method==='POST' && url==='/api/report') {
    try {
      const user = getUser(req);
      const body = await readBody(req);
      let data; try { data = JSON.parse(body); } catch(e) { return json(res,400,{error:'Invalid body'}); }
      const { type, severity, title, description, question, page, userAgent } = data;
      if (!title || !description) return json(res,400,{error:'title and description required'});
      await pool.query(
        `INSERT INTO bug_reports (user_id, type, severity, title, description, question, page, user_agent, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [user?.userId||null, type||'other', severity||'medium', title.slice(0,200), description.slice(0,2000), (question||'').slice(0,500)||null, page||null, (userAgent||'').slice(0,300), nowSec()]
      );
      return json(res,200,{ok:true});
    } catch(e){return json(res,500,{error:e.message});}
  }

  // ── FAVICON ──────────────────────────────────────────────
  if (url === '/favicon.svg' || url === '/favicon.ico') {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="7" fill="#1A1814"/>
  <path d="M16 3L28 9.5V22.5L16 29L4 22.5V9.5L16 3Z" fill="white" fill-opacity=".12"/>
  <path d="M16 3L28 9.5V22.5L16 29L4 22.5V9.5L16 3Z" stroke="white" stroke-width="1.5" stroke-linejoin="round"/>
  <path d="M16 9L22 20H10L16 9Z" fill="white" fill-opacity=".9"/>
  <circle cx="16" cy="17" r="1.5" fill="#1A1814"/>
</svg>`;
    res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' });
    return res.end(svg);
  }

  // ── STATIC FILES ─────────────────────────────────────────
  let filePath=path.join(__dirname,req.url.split('?')[0]);
  if(req.url.split('?')[0]==='/') filePath=path.join(__dirname,'landing.html');
  const ext=path.extname(filePath);
  const ct=ext==='.html'?'text/html':ext==='.js'?'application/javascript':ext==='.css'?'text/css':ext==='.json'?'application/json':'text/plain';
  fs.readFile(filePath,(err,content)=>{
    if(err){res.writeHead(404,{'Content-Type':'text/plain'});res.end('Not found: '+req.url);return;}
    res.writeHead(200,{'Content-Type':ct,'Access-Control-Allow-Origin':'*'});
    res.end(content);
  });
});

initDB().then(async ()=>{
  await seedSchools();
  server.listen(PORT,()=>{
    console.log(`Server on port ${PORT}`);
    console.log(`Stripe: ${STRIPE_SECRET_KEY?'configured':'NOT configured'}`);
    console.log(`Admin secret: ${ADMIN_SECRET?'SET':'NOT SET'}`);
    console.log(`Anthropic key: ${process.env.ANTHROPIC_API_KEY?'SET':'NOT SET'}`);
  });

  // ── WEBSOCKET SERVER ──────────────────────────────────────
  const wss = new WebSocketServer({ server });
  wss.on('connection', (ws, req) => {
    const params = new URLSearchParams(req.url.split('?')[1]||'');
    const token = params.get('token');
    const code = params.get('code');
    if (!token || !code) { ws.close(1008, 'Missing token or code'); return; }
    const user = verifyToken(token);
    if (!user) { ws.close(1008, 'Invalid token'); return; }

    // Verify membership then register
    pool.query('SELECT 1 FROM party_members WHERE party_id=$1 AND user_id=$2', [code, user.userId])
      .then(r => {
        if (!r.rows[0]) { ws.close(1008, 'Not a member of this party'); return; }
        if (!partyClients.has(code)) partyClients.set(code, new Map());
        partyClients.get(code).set(user.userId, ws);

        // Broadcast member joined
        broadcastToParty(code, { type: 'member_online', userId: user.userId }, user.userId);
        ws.send(JSON.stringify({ type: 'connected', userId: user.userId, partyId: code }));

        ws.on('close', () => {
          partyClients.get(code)?.delete(user.userId);
          if (partyClients.get(code)?.size === 0) partyClients.delete(code);
          broadcastToParty(code, { type: 'member_offline', userId: user.userId });
        });

        ws.on('error', () => {
          partyClients.get(code)?.delete(user.userId);
        });
      })
      .catch(() => ws.close(1011, 'Server error'));
  });
}).catch(err=>{console.error('DB init failed:',err.message);process.exit(1);});
