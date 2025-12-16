// server.js
// Bidibet server (merged + cancel-cutoff + cancel endpoints + respond route)
// UPDATED: attach names to bet payloads and include names in cancel emits; added /api/requests/:id/respond

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const session = require('express-session');
const path = require('path');
const http = require('http');

const app = express();

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'bidibet.db');
const WEB_DIR = path.join(__dirname, '../web'); // adjust if your web folder is different

app.set('trust proxy', 1);

app.use(bodyParser.json());
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

const isProd = process.env.NODE_ENV === 'production' || process.env.USE_SECURE_COOKIE === 'true';

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'BIDIBET_SECRET_KEY_CHANGE_THIS',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60,
    secure: !!isProd,
    sameSite: isProd ? 'none' : 'lax',
  },
});
app.use(sessionMiddleware);

app.use(express.static(WEB_DIR));
app.use('/logos', express.static(path.join(WEB_DIR, 'logos')));

app.get('/', (req, res) => {
  res.sendFile(path.join(WEB_DIR, 'index.html'));
});
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(WEB_DIR, 'dashboard.html'));
});

//app.get('/', (req, res) => res.sendFile(path.join(WEB_DIR, 'index.html')));
//app.get('/', (req, res) => res.sendFile(path.join(WEB_DIR, 'dashboard.html')));

// --- DB init + migration helper ---
const db = new sqlite3.Database(DB_FILE);

// Promisified helpers
function get(sql, params = []) {
  return new Promise((resolve, reject) =>
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)))
  );
}
function all(sql, params = []) {
  return new Promise((resolve, reject) =>
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)))
  );
}
function run(sql, params = []) {
  return new Promise((resolve, reject) =>
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    })
  );
}

/* ============================
   NEW: User-name resolution helpers
   - getUserNamesMap(userIds)
   - attachNamesToBets(bets)
   These reuse your existing `get`/`all` helpers.
   ============================ */

async function getUserNamesMap(userIds) {
  try {
    const uniq = Array.from(new Set((userIds || []).map(x => Number(x)).filter(x => !isNaN(x))));
    if (uniq.length === 0) return {};
    const placeholders = uniq.map(() => '?').join(',');
    const sql = `SELECT id, name FROM users WHERE id IN (${placeholders})`;
    const rows = await all(sql, uniq);
    const map = {};
    for (const r of rows) {
      map[String(r.id)] = r.name || String(r.id);
    }
    return map;
  } catch (e) {
    console.warn('getUserNamesMap failed', e && e.message);
    return {};
  }
}

async function attachNamesToBets(bets) {
  if (!Array.isArray(bets) || bets.length === 0) return bets;
  const ids = [];
  for (const b of bets) {
    if (!b) continue;
    if (b.from_user_id) ids.push(b.from_user_id);
    else if (typeof b.from === 'number') ids.push(b.from);
    if (b.to_user_id) ids.push(b.to_user_id);
    else if (typeof b.to === 'number') ids.push(b.to);
  }
  const map = await getUserNamesMap(ids);
  for (const b of bets) {
    if (!b) continue;
    if (!b.fromName) {
      if (b.from_user_id && map[String(b.from_user_id)]) b.fromName = map[String(b.from_user_id)];
      else if (typeof b.from === 'number' && map[String(b.from)]) b.fromName = map[String(b.from)];
      else if (b.from && typeof b.from === 'string') b.fromName = b.from;
      else b.fromName = b.fromName || '';
    }
    if (!b.toName) {
      if (b.to_user_id && map[String(b.to_user_id)]) b.toName = map[String(b.to_user_id)];
      else if (typeof b.to === 'number' && map[String(b.to)]) b.toName = map[String(b.to)];
      else if (b.to && typeof b.to === 'string') b.toName = b.to;
      else b.toName = b.toName || '';
    }
  }
  return bets;
}

/* ============================ end helpers ============================ */

db.serialize(() => {
  db.run(
    `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      mobile TEXT,
      passhash TEXT NOT NULL,
      wins INTEGER DEFAULT 0,
      losses INTEGER DEFAULT 0,
      totalWin REAL DEFAULT 0
    )
  `
  );

  db.run(
    `
    CREATE TABLE IF NOT EXISTS teams (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      slug TEXT NOT NULL UNIQUE,
      logo TEXT
    )
  `
  );

  db.run(
    `
    CREATE TABLE IF NOT EXISTS matches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      date TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      winner TEXT,
      loser TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(created_by) REFERENCES users(id)
    )
  `
  );

  db.run(
    `
    CREATE TABLE IF NOT EXISTS bets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user_id INTEGER NOT NULL,
      to_user_id INTEGER NOT NULL,
      match_id INTEGER,
      match_title TEXT NOT NULL,
      amount REAL NOT NULL,
      team_supported TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      settled INTEGER DEFAULT 0,
      FOREIGN KEY(from_user_id) REFERENCES users(id),
      FOREIGN KEY(to_user_id) REFERENCES users(id),
      FOREIGN KEY(match_id) REFERENCES matches(id)
    )
  `
  );

  db.run(
    `
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      text TEXT NOT NULL
    )
  `
  );

  // Ensure settings table exists as well (for cutoff)
  db.run(
    `
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `
  );

  (async () => {
    try {
      const cols = await all("PRAGMA table_info('alerts')");
      const existing = cols.map((c) => c.name);
      if (!existing.includes('username')) {
        console.log('Migration: adding username column to alerts table');
        await run('ALTER TABLE alerts ADD COLUMN username TEXT');
      }
      if (!existing.includes('time')) {
        console.log('Migration: adding time column to alerts table');
        await run('ALTER TABLE alerts ADD COLUMN time TEXT');
        try {
          await run("UPDATE alerts SET time = datetime('now') WHERE time IS NULL");
        } catch (e) {
          console.warn('Could not populate alerts.time for existing rows (non-fatal):', e && e.message);
        }
      }
    } catch (err) {
      console.warn('alerts migration check failed (non-fatal):', err && err.message);
    }

    try {
      const bcols = await all("PRAGMA table_info('bets')");
      const bnames = bcols.map((c) => c.name);
      if (!bnames.includes('settled')) {
        console.log('Migration: adding settled column to bets table');
        await run('ALTER TABLE bets ADD COLUMN settled INTEGER DEFAULT 0');
      }
    } catch (err) {
      console.warn('bets migration check failed (non-fatal):', err && err.message);
    }
  })();
});

// simple slug helper
function slugify(name) {
  return name
    .toString()
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9\-]/g, '');
}

// ---------- HTTP + Socket.IO ----------
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server, { cors: { origin: true, credentials: true } });

io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

const userIdSockets = new Map();
const userNameSockets = new Map();

function addToMapSet(map, key, socket) {
  if (!key) return;
  const k = String(key);
  if (!map.has(k)) map.set(k, new Set());
  map.get(k).add(socket);
}
function removeFromMapSet(map, key, socket) {
  if (!key) return;
  const k = String(key);
  const s = map.get(k);
  if (!s) return;
  s.delete(socket);
  if (s.size === 0) map.delete(k);
}

function registerSocketForUser({ userId, userName }, socket) {
  if (userId) {
    const idKey = String(userId);
    addToMapSet(userIdSockets, idKey, socket);
    try {
      socket.join(`uid:${idKey}`);
    } catch (e) {}
  }
  if (userName) {
    const uname = String(userName).toLowerCase();
    addToMapSet(userNameSockets, uname, socket);
    try {
      socket.join(`uname:${uname}`);
    } catch (e) {}
  }

  socket._registeredUserId = userId ? String(userId) : socket._registeredUserId || null;
  socket._registeredUserName = userName ? String(userName).toLowerCase() : socket._registeredUserName || null;
  console.log(
    `Registered socket ${socket.id} for userId=${socket._registeredUserId} userName=${socket._registeredUserName}`
  );
}
function unregisterSocket(socket) {
  try {
    if (socket._registeredUserId) removeFromMapSet(userIdSockets, socket._registeredUserId, socket);
    if (socket._registeredUserName) removeFromMapSet(userNameSockets, socket._registeredUserName, socket);
    console.log(`Unregistered socket ${socket.id} for userId=${socket._registeredUserId} userName=${socket._registeredUserName}`);
  } catch (e) {
    console.warn('unregisterSocket error', e && e.message);
  }
}

function emitToUser(target, event, payload) {
  let sent = 0;
  try {
    if (target && typeof target === 'object' && (target.id || target.name)) {
      const idKey = target.id ? String(target.id) : null;
      const nameKey = target.name ? String(target.name).toLowerCase() : null;

      if (idKey && userIdSockets.has(idKey)) {
        for (const s of userIdSockets.get(idKey)) {
          try {
            s.emit(event, payload);
            sent++;
          } catch (e) {}
        }
      }
      if (nameKey && userNameSockets.has(nameKey)) {
        for (const s of userNameSockets.get(nameKey)) {
          try {
            s.emit(event, payload);
            sent++;
          } catch (e) {}
        }
      }

      try {
        if (idKey) {
          io.to(`uid:${idKey}`).emit(event, payload);
        }
        if (nameKey) {
          io.to(`uname:${nameKey}`).emit(event, payload);
        }
      } catch (e) {}

      console.log(`emitToUser(object) event='${event}' attempted sockets=${sent} for id=${idKey} name=${nameKey}`);
      return sent;
    }

    if (!isNaN(Number(target))) {
      const idKey = String(target);
      if (userIdSockets.has(idKey)) {
        for (const s of userIdSockets.get(idKey)) {
          try {
            s.emit(event, payload);
            sent++;
          } catch (e) {}
        }
      }
      try {
        io.to(`uid:${idKey}`).emit(event, payload);
      } catch (e) {}
      console.log(`emitToUser(id) event='${event}' attempted sockets=${sent} for id=${idKey}`);
      return sent;
    }

    if (typeof target === 'string') {
      const nameKey = target.toLowerCase();
      if (userNameSockets.has(nameKey)) {
        for (const s of userNameSockets.get(nameKey)) {
          try {
            s.emit(event, payload);
            sent++;
          } catch (e) {}
        }
      }
      try {
        io.to(`uname:${nameKey}`).emit(event, payload);
      } catch (e) {}
      console.log(`emitToUser(name) event='${event}' attempted sockets=${sent} for name=${nameKey}`);
      return sent;
    }

    console.log(`emitToUser: invalid target type for event='${event}'`);
    return sent;
  } catch (err) {
    console.warn('emitToUser error', err && err.message);
    return sent;
  }
}

io.on('connection', (socket) => {
  console.log('Socket connected', socket.id);

  try {
    const sessUser = socket.request && socket.request.session && socket.request.session.user;
    if (sessUser && sessUser.id) {
      registerSocketForUser({ userId: sessUser.id, userName: sessUser.name }, socket);
    }
  } catch (e) {
    console.warn('auto-register from session failed', e && e.message);
  }

  socket.on('identify', (data) => {
    try {
      if (!data) return;
      const uid = data.userId || data.user || data.id || null;
      const uname = data.name || data.username || null;
      registerSocketForUser({ userId: uid, userName: uname }, socket);
    } catch (e) {
      console.warn('identify handler error', e && e.message);
    }
  });

  socket.on('setUserName', (name) => {
    try {
      if (!name) return;
      registerSocketForUser({ userId: socket._registeredUserId || null, userName: name }, socket);
    } catch (e) {
      console.warn('setUserName handler error', e && e.message);
    }
  });

  socket.on('disconnect', () => {
    try {
      unregisterSocket(socket);
      console.log('Socket disconnected', socket.id);
    } catch (e) {
      console.warn('disconnect cleanup error', e && e.message);
    }
  });
});

// ---------- Settings helpers (for global cutoff) ----------
async function getSetting(key) {
  try {
    const row = await get('SELECT value FROM settings WHERE key = ?', [key]);
    return row ? row.value : null;
  } catch (e) {
    console.warn('getSetting error', key, e && e.message);
    return null;
  }
}
async function setSetting(key, value) {
  try {
    await run('INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)', [key, value]);
    return true;
  } catch (e) {
    console.warn('setSetting error', key, e && e.message);
    return false;
  }
}
const CANCEL_CUTOFF_KEY = 'cancel_cutoff_hhmm'; // stored value like "19:00"

// Parse match date + cutoff HH:MM into Date
function parseMatchCutoffDatetime(matchDateText, cutoffHHMM) {
  if (!matchDateText || !cutoffHHMM) return null;
  try {
    const candidate = `${matchDateText} ${cutoffHHMM}`;
    let dt = new Date(candidate);
    if (!isNaN(dt.getTime())) return dt;

    const parts = matchDateText.trim().split(/[\-\/ ]+/);
    if (parts.length === 3) {
      const day = parts[0];
      const monthName = parts[1];
      const year = parts[2];
      const monthNames = ['jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec'];
      const mIndex = monthNames.indexOf(monthName.toString().toLowerCase().slice(0,3));
      if (mIndex >= 0) {
        const iso = `${year}-${String(mIndex+1).padStart(2,'0')}-${String(day).padStart(2,'0')}T${cutoffHHMM}:00`;
        dt = new Date(iso);
        if (!isNaN(dt.getTime())) return dt;
      }
    }

    const base = new Date(matchDateText);
    if (!isNaN(base.getTime())) {
      const [hh, mm] = cutoffHHMM.split(':').map(x => parseInt(x,10) || 0);
      base.setHours(hh, mm, 0, 0);
      return base;
    }
  } catch (e) {}
  return null;
}

// ---------- Auth ----------
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
    const exists = await get('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (exists) return res.status(409).json({ error: 'Email exists' });
    const hash = await bcrypt.hash(password, 10);
    await run('INSERT INTO users (name,email,mobile,passhash) VALUES (?,?,?,?)', [
      name,
      email.toLowerCase(),
      mobile || '',
      hash,
    ]);
    const user = await get('SELECT id,name,email FROM users WHERE email = ?', [email.toLowerCase()]);
    req.session.user = user;
    res.json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password, remember } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
    const u = await get('SELECT id,name,email,passhash FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!u) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, u.passhash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.user = { id: u.id, name: u.name, email: u.email };
    if (remember) req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30;
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server' });
  }
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.user) return res.json({ user: req.session.user });
  res.status(401).json({ error: 'Not logged in' });
});

app.post('/api/logout', (req, res) => {
  const uid = req.session && req.session.user && req.session.user.id;
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ---------- Teams ----------
app.get('/api/teams', async (req, res) => {
  try {
    const rows = await all('SELECT id,name,slug,logo FROM teams ORDER BY name COLLATE NOCASE');
    res.json({ teams: rows });
  } catch (err) {
    console.error('Teams error:', err);
    res.status(500).json({ error: 'server' });
  }
});

async function ensureTeamByName(name) {
  const nm = (name || '').trim();
  if (!nm) throw new Error('empty name');
  const existing = await get('SELECT id,name,slug,logo FROM teams WHERE name = ?', [nm]);
  if (existing) return existing;
  const slug = slugify(nm) || `team-${Date.now()}`;
  await run('INSERT INTO teams (name,slug,logo) VALUES (?,?,?)', [nm, slug, null]);
  const inserted = await get('SELECT id,name,slug,logo FROM teams WHERE name = ?', [nm]);
  return inserted;
}

// ---------- Matches ----------
app.post('/api/admin/create-match', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const { title, date } = req.body;
    if (!title || !date) return res.status(400).json({ error: 'Missing title or date' });
    const createdBy = req.session.user.id;

    let teams = [];
    if (title.includes(' VS ')) teams = title.split(' VS ');
    else if (title.includes(' vs ')) teams = title.split(' vs ');
    else if (title.includes(' v ')) teams = title.split(' v ');
    else if (title.includes('-')) teams = title.split('-');
    else teams = title.split(' ');

    teams = teams.map((s) => s.trim()).filter(Boolean);
    for (const t of teams) {
      try {
        await ensureTeamByName(t);
      } catch (e) {
        console.warn('team create failed', t, e);
      }
    }

    const result = await run('INSERT INTO matches (title, date, created_by) VALUES (?,?,?)', [title, date, createdBy]);
    const insertedId = result.lastID || result.id;
    const match = await get('SELECT m.*, u.name as created_by_name FROM matches m JOIN users u ON m.created_by = u.id WHERE m.id = ?', [
      insertedId,
    ]);
    res.json({ success: true, match });
  } catch (err) {
    console.error('Create match error:', err);
    res.status(500).json({ error: 'server' });
  }
});

app.get('/api/matches', async (req, res) => {
  try {
    const rows = await all(
      `SELECT m.id, m.title, m.date, m.winner, m.loser, m.created_by, u.name as created_by_name, m.created_at
       FROM matches m
       JOIN users u ON m.created_by = u.id
       ORDER BY datetime(m.date) DESC, m.created_at DESC`
    );
    res.json({ matches: rows });
  } catch (err) {
    console.error('List matches error:', err);
    res.status(500).json({ error: 'server' });
  }
});

app.post('/api/matches/:id/result', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const userId = req.session.user.id;
    const matchId = Number(req.params.id);
    const { winner, loser } = req.body;
    if (!winner || !loser) return res.status(400).json({ error: 'Missing winner or loser' });

    const match = await get('SELECT * FROM matches WHERE id = ?', [matchId]);
    if (!match) return res.status(404).json({ error: 'Match not found' });
    if (match.created_by !== userId) return res.status(403).json({ error: 'Only the match creator can set result' });

    await run('UPDATE matches SET winner = ?, loser = ? WHERE id = ?', [winner, loser, matchId]);

    try { await ensureTeamByName(winner); } catch (e) {}
    try { await ensureTeamByName(loser); } catch (e) {}

    const matchTitle = match.title;

    let unsettledBets = [];
    try {
      unsettledBets = await all(
        `SELECT * FROM bets WHERE match_title = ? AND (status = 'approved' OR status = 'confirmed') AND (settled IS NULL OR settled = 0)`,
        [matchTitle]
      );
    } catch (e) {
      console.warn('Failed to query unsettled bets', e && e.message);
      unsettledBets = [];
    }

    let processed = 0;
    for (const b of unsettledBets) {
      try {
        const betId = b.id;
        const amount = Number(b.amount || 0) || 0;
        const fromId = b.from_user_id;
        const toId = b.to_user_id;
        const fromSupported = (b.team_supported || '').toString();

        let toSupported = null;
        try {
          let teams = [];
          if (matchTitle.includes(' VS ')) teams = matchTitle.split(' VS ');
          else if (matchTitle.includes(' vs ')) teams = matchTitle.split(' vs ');
          else if (matchTitle.includes(' v ')) teams = matchTitle.split(' v ');
          else if (matchTitle.includes('-')) teams = matchTitle.split('-');
          teams = teams.map(s => s.trim()).filter(Boolean);
          if (teams.length >= 2) {
            const t1 = teams[0], t2 = teams[1];
            if (String(fromSupported).toLowerCase() === String(t1).toLowerCase()) toSupported = t2;
            else if (String(fromSupported).toLowerCase() === String(t2).toLowerCase()) toSupported = t1;
            else {
              toSupported = (String(t1).toLowerCase() !== String(fromSupported).toLowerCase()) ? t1 : t2;
            }
          }
        } catch (e) {
          toSupported = null;
        }

        let outcomeFrom = 'neutral';
        if (fromSupported && String(fromSupported).toLowerCase() === String(winner).toLowerCase()) outcomeFrom = 'won';
        else if (fromSupported && String(fromSupported).toLowerCase() === String(loser).toLowerCase()) outcomeFrom = 'lost';
        else outcomeFrom = 'neutral';

        let outcomeTo = 'neutral';
        if (toSupported) {
          if (String(toSupported).toLowerCase() === String(winner).toLowerCase()) outcomeTo = 'won';
          else if (String(toSupported).toLowerCase() === String(loser).toLowerCase()) outcomeTo = 'lost';
          else outcomeTo = 'neutral';
        } else {
          if (outcomeFrom === 'won') outcomeTo = 'lost';
          else if (outcomeFrom === 'lost') outcomeTo = 'won';
          else outcomeTo = 'neutral';
        }

        const newStatus = (outcomeFrom === 'won') ? 'won' : (outcomeFrom === 'lost' ? 'lost' : 'settled');

        try {
          await run('UPDATE bets SET status = ?, settled = 1 WHERE id = ?', [newStatus, betId]);
        } catch (e) {
          console.warn('Failed to mark bet settled', betId, e && e.message);
        }

        if (outcomeFrom === 'won') {
          try {
            await run('UPDATE users SET wins = COALESCE(wins,0) + 1, totalWin = COALESCE(totalWin,0) + ? WHERE id = ?', [amount, fromId]);
          } catch (e) {
            console.warn('Failed to update winner (from) stats', fromId, e && e.message);
          }
        } else if (outcomeFrom === 'lost') {
          try {
            await run('UPDATE users SET losses = COALESCE(losses,0) + 1, totalWin = COALESCE(totalWin,0) - ? WHERE id = ?', [amount, fromId]);
          } catch (e) {
            console.warn('Failed to update loser (from) stats', fromId, e && e.message);
          }
        }

        if (toId) {
          if (outcomeTo === 'won') {
            try {
              await run('UPDATE users SET wins = COALESCE(wins,0) + 1, totalWin = COALESCE(totalWin,0) + ? WHERE id = ?', [amount, toId]);
            } catch (e) {
              console.warn('Failed to update winner (to) stats', toId, e && e.message);
            }
          } else if (outcomeTo === 'lost') {
            try {
              await run('UPDATE users SET losses = COALESCE(losses,0) + 1, totalWin = COALESCE(totalWin,0) - ? WHERE id = ?', [amount, toId]);
            } catch (e) {
              console.warn('Failed to update loser (to) stats', toId, e && e.message);
            }
          }
        }

        try {
          const fromUserRow = await get('SELECT id,name FROM users WHERE id = ?', [fromId]);
          const toUserRow = await get('SELECT id,name FROM users WHERE id = ?', [toId]);

          const payload = {
            betId: betId,
            match: matchTitle,
            amount,
            fromSupported,
            toSupported,
            status: newStatus,
            outcomeFrom,
            outcomeTo,
            time: new Date().toISOString(),
            fromUserId: fromId,
            fromName: fromUserRow ? fromUserRow.name : null,
            toUserId: toId,
            toName: toUserRow ? toUserRow.name : null,
          };

          if (fromUserRow) emitToUser({ id: fromUserRow.id, name: fromUserRow.name }, 'bet_settled', payload);
          if (toUserRow) emitToUser({ id: toUserRow.id, name: toUserRow.name }, 'bet_settled', payload);
        } catch (e) {
          console.warn('Failed to emit bet_settled for bet', betId, e && e.message);
        }

        processed++;
      } catch (err) {
        console.warn('Error while processing bet', b && b.id, err && err.message);
      }
    }

    const updatedMatch = await get('SELECT m.*, u.name as created_by_name FROM matches m JOIN users u ON m.created_by = u.id WHERE m.id = ?', [
      matchId,
    ]);

    res.json({ success: true, match: updatedMatch, settled_count: processed });
  } catch (err) {
    console.error('Set result error:', err && (err.stack || err));
    res.status(500).json({ error: 'server' });
  }
});

// ---------- Points ----------
app.get('/api/points', async (req, res) => {
  try {
    const rows = await all(
      `SELECT id, title, date, winner, loser, created_at
       FROM matches
       WHERE winner IS NOT NULL
       ORDER BY datetime(created_at) DESC`
    );

    const map = new Map();
    function ensure(name) {
      if (!map.has(name)) map.set(name, { team: name, M: 0, W: 0, L: 0, pts: 0, lastResults: [] });
      return map.get(name);
    }

    for (const m of rows) {
      const w = m.winner,
        l = m.loser;
      if (!w || !l) continue;
      const tw = ensure(w),
        tl = ensure(l);
      tw.M += 1;
      tw.W += 1;
      tw.pts = tw.W * 2;
      tl.M += 1;
      tl.L += 1;
      tl.pts = tl.W * 2;
      tw.lastResults.push({ result: 'W', when: m.created_at });
      tl.lastResults.push({ result: 'L', when: m.created_at });
    }

    const teamsFromDb = await all('SELECT name,slug,logo FROM teams');
    const teamsByName = new Map(teamsFromDb.map((t) => [t.name, t]));
    const teams = Array.from(map.values()).map((t) => {
      const dbt = teamsByName.get(t.team);
      const logo = dbt ? dbt.logo : null;
      const slug = dbt ? dbt.slug : null;
      const last5 = t.lastResults.slice(0, 5).map((r) => r.result);
      return { team: t.team, slug, logo, M: t.M, W: t.W, L: t.L, Pts: t.pts, last5 };
    });

    teams.sort((a, b) => {
      if (b.Pts !== a.Pts) return b.Pts - a.Pts;
      if (b.W !== a.W) return b.W - a.W;
      return a.team.localeCompare(b.team);
    });

    res.json({ teams });
  } catch (err) {
    console.error('Points error:', err);
    res.status(500).json({ error: 'server' });
  }
});

// ---------- Users / Leaderboard ----------
app.get('/api/users', async (req, res) => {
  try {
    const users = await all('SELECT id,name,email,wins,losses,totalWin FROM users ORDER BY totalWin DESC, wins DESC');
    res.json({ users });
  } catch (err) {
    console.error('Users error:', err);
    res.status(500).json({ error: 'server' });
  }
});

/* -----------------------
   Bets core endpoints + compatibility wrappers
   ----------------------- */

async function createBetInternal(fromUserId, toUserId, matchTitle, amount, team) {
  let matchRow = null;
  try {
    matchRow = await get('SELECT id, title, date FROM matches WHERE title = ?', [matchTitle]);
  } catch (e) { matchRow = null; }

  const result = await run(
    `INSERT INTO bets (from_user_id, to_user_id, match_id, match_title, amount, team_supported, status)
               VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
    [fromUserId, toUserId, matchRow ? matchRow.id : null, matchTitle, amount, team]
  );
  const id = result.lastID || result.id;
  const betRow = await get('SELECT * FROM bets WHERE id = ?', [id]);
  return betRow;
}

app.post('/api/bets/create', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const fromUserId = req.session.user.id;
    let { toUserId, matchId, matchTitle, amount, team } = req.body;
    if (!toUserId && req.body.to) {
      const maybe = await get('SELECT id FROM users WHERE name = ?', [req.body.to]);
      if (maybe) toUserId = maybe.id;
    }
    if (!toUserId || !matchTitle || !amount || !team) return res.status(400).json({ error: 'Missing fields' });
    const matchRow = await get(
      'SELECT winner FROM matches WHERE id = ? OR title = ?',
      [matchId, matchTitle]
    );
    if (matchRow && matchRow.winner) {
      return res.status(400).json({
        error: 'Bet not allowed. Match has been completed.'
      });
    }

    const betRow = await createBetInternal(fromUserId, toUserId, matchTitle, amount, team);
    const fromUser = await get('SELECT id,name,email FROM users WHERE id = ?', [fromUserId]);
    const toUser = await get('SELECT id,name,email FROM users WHERE id = ?', [toUserId]);

    // try to get match date
    let matchDate = null;
    try {
      const mrow = betRow && betRow.match_id ? await get('SELECT date FROM matches WHERE id = ?', [betRow.match_id]) : await get('SELECT date FROM matches WHERE title = ?', [betRow.match_title]);
      if (mrow) matchDate = mrow.date;
    } catch (e) { matchDate = null; }

    const payload = {
      id: 'betreq_' + (betRow.id || Date.now()),
      betId: betRow.id,
      fromUserId: fromUserId,
      fromName: fromUser ? fromUser.name : (req.session.user.name || 'Unknown'),
      toUserId: toUserId,
      toName: toUser ? toUser.name : null,
      match: betRow.match_title,
      match_date: matchDate || null,
      amount: betRow.amount,
      team: betRow.team_supported,
      status: betRow.status,
      time: betRow.created_at || new Date().toISOString(),
    };

    try {
      const alertId = 'a_' + Date.now() + Math.floor(Math.random() * 999);
      const text = `${payload.fromName} requested a bet of ${payload.amount} on ${payload.team} (${payload.match})`;
      const time = payload.time;
      await run('INSERT OR REPLACE INTO alerts (id, username, text, time) VALUES (?,?,?,?)', [
        alertId,
        (toUser && toUser.name) || '',
        text,
        time,
      ]);
    } catch (err) {
      console.warn('Could not insert alert row (non-fatal):', err && err.message);
    }

    try {
      emitToUser({ id: toUserId, name: (toUser && toUser.name) || '' }, 'bet_request', payload);
    } catch (e) {
      console.warn('emit bet_request failed', e && e.message);
    }

    res.json({ success: true, betId: betRow.id });
  } catch (err) {
    console.error('Create bet error:', err);
    res.status(500).json({ error: 'server' });
  }
});

app.get('/api/bets/incoming', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const userId = req.session.user.id;
    const rows = await all(
      `SELECT b.id, b.from_user_id, fu.name as from_name, fu.email as from_email,
              b.match_id, b.match_title as match, b.amount, b.team_supported as team, b.status, b.created_at
       FROM bets b
       LEFT JOIN users fu ON fu.id = b.from_user_id
       WHERE b.to_user_id = ? AND b.status = 'pending'
       ORDER BY b.created_at DESC`,
      [userId]
    );
    res.json({ bets: rows });
  } catch (err) {
    console.error('Incoming bets error:', err);
    res.status(500).json({ error: 'server' });
  }
});

// Provide a general bets.list endpoint used by the dashboard (compat)
app.get('/api/bets/list', async (req, res) => {
  try {
    const rows = await all('SELECT * FROM bets ORDER BY created_at DESC');
    // Enrich rows with fromName / toName before returning
    try {
      await attachNamesToBets(rows);
    } catch (e) {
      console.warn('attachNamesToBets failed for /api/bets/list', e && e.message);
    }
    res.json({ bets: rows });
  } catch (err) {
    console.error('GET /api/bets/list error', err);
    res.status(500).json({ bets: [] });
  }
});

/* === New cancellation endpoints === */

// Get global cancel cutoff (returns { cutoff: "19:00" } or null)
app.get('/api/admin/cancel-cutoff', async (req, res) => {
  try {
    const v = await getSetting(CANCEL_CUTOFF_KEY);
    res.json({ cutoff: v || null });
  } catch (err) {
    console.error('GET /api/admin/cancel-cutoff error', err && err.stack ? err.stack : err);
    res.status(500).json({ error: 'server' });
  }
});

// Set cutoff (admin). Body: { cutoff: "19:00" }
app.post('/api/admin/cancel-cutoff', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const cutoff = (req.body && req.body.cutoff) ? String(req.body.cutoff).trim() : null;
    if (!cutoff || !/^\d{1,2}:\d{2}$/.test(cutoff)) return res.status(400).json({ error: 'Invalid cutoff format (expected HH:MM)' });
    const ok = await setSetting(CANCEL_CUTOFF_KEY, cutoff);
    if (!ok) return res.status(500).json({ error: 'failed to save' });
    res.json({ success: true, cutoff });
  } catch (err) {
    console.error('POST /api/admin/cancel-cutoff error', err && err.stack ? err.stack : err);
    res.status(500).json({ error: 'server' });
  }
});

// Cancel a single bet by id
app.post('/api/bets/:id/cancel', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const uid = req.session.user.id;
    const bid = Number(req.params.id);
    if (!bid) return res.status(400).json({ error: 'Missing bet id' });

    const bet = await get('SELECT * FROM bets WHERE id = ?', [bid]);
    if (!bet) return res.status(404).json({ error: 'Bet not found' });

    // Only involved users can cancel: from_user_id or to_user_id
    const allowed = (String(bet.from_user_id) === String(uid)) || (String(bet.to_user_id) === String(uid));
    if (!allowed) return res.status(403).json({ error: 'Not a participant' });

    // check cutoff
    let cutoffAllowed = true;
    try {
      const cutoffHHMM = await getSetting(CANCEL_CUTOFF_KEY);
      if (cutoffHHMM) {
        let matchRow = null;
        if (bet.match_id) matchRow = await get('SELECT id, title, date, created_by FROM matches WHERE id = ?', [bet.match_id]);
        if (!matchRow) {
          matchRow = await get('SELECT id, title, date, created_by FROM matches WHERE title = ?', [bet.match_title]);
        }
        if (matchRow && matchRow.date) {
          const cutoffDt = parseMatchCutoffDatetime(matchRow.date, cutoffHHMM);
          if (cutoffDt) {
            const now = new Date();
            if (!(now.getTime() < cutoffDt.getTime())) {
              cutoffAllowed = false;
            }
          }
        }
      }
    } catch (e) {
      console.warn('cutoff check failed (allowing by default):', e && e.message);
      cutoffAllowed = true;
    }

    if (!cutoffAllowed) return res.status(403).json({ error: 'Cancellation window closed' });

    // mark cancelled
    await run('UPDATE bets SET status = ?, settled = 1 WHERE id = ?', ['cancelled', bid]);

    // insert alerts for both users
    const otherUserId = String(bet.from_user_id) === String(uid) ? bet.to_user_id : bet.from_user_id;
    const meRow = await get('SELECT id,name FROM users WHERE id = ?', [uid]);
    const otherRow = otherUserId ? await get('SELECT id,name FROM users WHERE id = ?', [otherUserId]) : null;
    const meName = meRow ? meRow.name : (req.session.user.name || 'User');
    const otherName = otherRow ? otherRow.name : (otherUserId || '');

    const text = `Bet has been cancelled with ${otherName || 'Unknown'}.`;
    const time = new Date().toISOString();
    try {
      const aid = 'a_' + Date.now() + Math.floor(Math.random() * 9999);
      await run('INSERT OR REPLACE INTO alerts (id, username, text, time) VALUES (?,?,?,?)', [aid, meName, text, time]);
      if (otherName) {
        const aid2 = 'a_' + (Date.now()+1) + Math.floor(Math.random() * 9999);
        await run('INSERT OR REPLACE INTO alerts (id, username, text, time) VALUES (?,?,?,?)', [aid2, otherName, text, time]);
      }
    } catch (e) { console.warn('insert alerts error', e && e.message); }

    // emit socket events (ENRICH payload with fromName/toName)
    try {
      const fromRow = bet.from_user_id ? await get('SELECT id,name FROM users WHERE id = ?', [bet.from_user_id]) : null;
      const toRow = bet.to_user_id ? await get('SELECT id,name FROM users WHERE id = ?', [bet.to_user_id]) : null;

      const payload = {
        betId: bid,
        match: bet.match_title,
        fromUserId: bet.from_user_id,
        toUserId: bet.to_user_id,
        cancelledBy: uid,
        text,
        time,
        fromName: fromRow ? fromRow.name : (bet.from || ''),
        toName: toRow ? toRow.name : (bet.to || '')
      };

      if (bet.from_user_id) emitToUser(String(bet.from_user_id), 'bet_cancelled', payload);
      if (bet.to_user_id) emitToUser(String(bet.to_user_id), 'bet_cancelled', payload);
    } catch (e) { console.warn('emit bet_cancelled failed', e && e.message); }

    res.json({ success: true, betId: bid });
  } catch (err) {
    console.error('POST /api/bets/:id/cancel error:', err && (err.stack || err));
    res.status(500).json({ error: 'server' });
  }
});


/* =========================
   REDEAL ENDPOINT (KEY ADDITION)
   ========================= */

app.post('/api/bets/:id/redeal', async (req, res) => {
  try {
    if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });

    const betId = Number(req.params.id);
    const newAmount = Number(req.body.amount);
    const userId = req.session.user.id;

    if (!newAmount || newAmount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    const bet = await get(`SELECT * FROM bets WHERE id = ?`, [betId]);
    if (!bet) return res.status(404).json({ error: 'Bet not found' });

    // Only receiver can redeal
    if (bet.to_user_id !== userId) {
      return res.status(403).json({ error: 'Not allowed to redeal this bet' });
    }

    const originalAmount = Number(bet.amount);

    // LOWER or SAME → AUTO CONFIRM
    if (newAmount <= originalAmount) {
      await run(`UPDATE bets SET amount = ?, status = 'confirmed' WHERE id = ?`, [newAmount, betId]);

      emitToUser({ id: bet.from_user_id }, 'bet_confirmed', {
        betId,
        amount: newAmount,
        message: `Bet redealed and confirmed for ₹${newAmount}`
      });

      return res.json({ success: true, message: `Redeal confirmed for ₹${newAmount}` });
    }

    // HIGHER → NEED APPROVAL
    await run(`UPDATE bets SET amount = ?, status = 'pending' WHERE id = ?`, [newAmount, betId]);

    emitToUser({ id: bet.from_user_id }, 'bet_redeal_request', {
      betId,
      amount: newAmount,
      message: `${req.session.user.name} wants to redeal bet for ₹${newAmount}`
    });

    return res.json({ success: true, message: 'Redeal request sent for approval' });

  } catch (err) {
    console.error('Redeal error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// === END OF FILE ===


// Cancel all bets for a match (match_id or match_title in body)
app.post('/api/bets/cancel-match', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const { match_id, match_title } = req.body || {};
    if (!match_id && !match_title) return res.status(400).json({ error: 'Missing match identifier' });

    let matchRow = null;
    if (match_id) matchRow = await get('SELECT * FROM matches WHERE id = ?', [match_id]);
    if (!matchRow && match_title) matchRow = await get('SELECT * FROM matches WHERE title = ?', [match_title]);
    if (!matchRow) return res.status(404).json({ error: 'Match not found' });

    // authorization: allow only match creator to cancel all (adjust if you have admin flag)
    if (String(matchRow.created_by) !== String(req.session.user.id)) {
      return res.status(403).json({ error: 'Only the match creator can cancel all bets for this match' });
    }

    // fetch affected bets
    const bets = await all('SELECT * FROM bets WHERE match_title = ? OR match_id = ?', [matchRow.title, matchRow.id]);
    if (!bets || bets.length === 0) return res.json({ success: true, cancelled_count: 0 });

    const now = new Date().toISOString();
    // update bets
    await run('UPDATE bets SET status = ?, settled = 1 WHERE match_title = ? OR match_id = ?', ['cancelled', matchRow.title, matchRow.id]);

    // for each bet, insert alerts for both users and emit
    for (const bet of bets) {
      try {
        const fromRow = bet.from_user_id ? await get('SELECT id,name FROM users WHERE id = ?', [bet.from_user_id]) : null;
        const toRow = bet.to_user_id ? await get('SELECT id,name FROM users WHERE id = ?', [bet.to_user_id]) : null;
        const nicknameA = fromRow ? fromRow.name : (bet.from || '');
        const nicknameB = toRow ? toRow.name : (bet.to || '');
        const text = `Bet has been cancelled with ${nicknameB || nicknameA}.`;
        const aid = 'a_' + Date.now() + Math.floor(Math.random() * 9999);
        if (nicknameA) await run('INSERT OR REPLACE INTO alerts (id, username, text, time) VALUES (?,?,?,?)', [aid, nicknameA, text, now]);
        if (nicknameB) {
          const aid2 = 'a_' + (Date.now()+1) + Math.floor(Math.random() * 9999);
          await run('INSERT OR REPLACE INTO alerts (id, username, text, time) VALUES (?,?,?,?)', [aid2, nicknameB, text, now]);
        }
        // emit real time (include fromName/toName)
        const payload = {
          betId: bet.id,
          match: matchRow.title,
          fromUserId: bet.from_user_id,
          toUserId: bet.to_user_id,
          cancelledBy: req.session.user.id,
          text,
          time: now,
          fromName: fromRow ? fromRow.name : (bet.from || ''),
          toName: toRow ? toRow.name : (bet.to || '')
        };
        if (bet.from_user_id) emitToUser(String(bet.from_user_id), 'bet_cancelled', payload);
        if (bet.to_user_id) emitToUser(String(bet.to_user_id), 'bet_cancelled', payload);
      } catch (e) {
        console.warn('per-bet cancel notification failed', e && e.message);
      }
    }

    res.json({ success: true, cancelled_count: bets.length, match: matchRow.title });
  } catch (err) {
    console.error('POST /api/bets/cancel-match error:', err && (err.stack || err));
    res.status(500).json({ error: 'server' });
  }
});

/* -----------------------
   Requests/respond route (NEW)
   ----------------------- */

// Respond to a request (approve/decline) - route: POST /api/requests/:id/respond
// Body: { approved: true/false, responder: 'Name (optional)' }
app.post('/api/requests/:id/respond', async (req, res) => {
  try {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Not logged in' });
    const responderId = req.session.user.id;
    const responderName = req.session.user.name || (req.body && req.body.responder) || '';
    const reqId = Number(req.params.id);
    if (!reqId) return res.status(400).json({ error: 'Missing/invalid request id' });

    // fetch bet/request
    const bet = await get('SELECT * FROM bets WHERE id = ?', [reqId]);
    if (!bet) return res.status(404).json({ error: 'Request not found' });

    // Only the intended recipient (to_user_id) can respond
    if (String(bet.to_user_id) !== String(responderId)) {
      return res.status(403).json({ error: 'Not authorized to respond' });
    }

    const approved = !!req.body.approved;

    // update bet status
    const newStatus = approved ? 'confirmed' : 'declined';
    await run('UPDATE bets SET status = ? WHERE id = ?', [newStatus, reqId]);

    // load user rows for names
    const fromRow = bet.from_user_id ? await get('SELECT id,name FROM users WHERE id = ?', [bet.from_user_id]) : null;
    const toRow = bet.to_user_id ? await get('SELECT id,name FROM users WHERE id = ?', [bet.to_user_id]) : null;

    const time = new Date().toISOString();
    const text = approved
      ? `${responderName} approved your bet of ${bet.amount} on ${bet.team_supported} (${bet.match_title})`
      : `${responderName} declined your bet of ${bet.amount} on ${bet.team_supported} (${bet.match_title})`;

    // insert alert for originator (from) and also for responder (to) so both see notifications
    try {
      if (fromRow && fromRow.name) {
        const aid = 'a_' + Date.now() + Math.floor(Math.random() * 9999);
        await run('INSERT OR REPLACE INTO alerts (id, username, text, time) VALUES (?,?,?,?)', [
          aid,
          fromRow.name,
          text,
          time,
        ]);
      }

      if (toRow && toRow.name) {
        const aid2 = 'a_' + (Date.now()+1) + Math.floor(Math.random() * 9999);
        const myText = approved ? `You approved bet ${reqId}` : `You declined bet ${reqId}`;
        await run('INSERT OR REPLACE INTO alerts (id, username, text, time) VALUES (?,?,?,?)', [
          aid2,
          toRow.name,
          myText,
          time,
        ]);
      }
    } catch (e) {
      console.warn('respond: alert insert failed', e && e.message);
    }

    // Build payload with fromName/toName included (enriched)
    const payload = {
      id: 'resp_' + reqId,
      betId: reqId,
      fromUserId: bet.from_user_id,
      toUserId: bet.to_user_id,
      fromName: fromRow ? fromRow.name : bet.from || '',
      toName: toRow ? toRow.name : bet.to || '',
      match: bet.match_title || bet.match,
      amount: bet.amount,
      team: bet.team_supported,
      status: newStatus,
      approved: approved,
      responder: responderName,
      time
    };

    // Emit to the originator (the requester) so they receive the notification
    try {
      if (bet.from_user_id) {
        emitToUser(String(bet.from_user_id), 'bet_response', payload);
      } else if (fromRow && fromRow.name) {
        emitToUser(fromRow.name, 'bet_response', payload);
      }
      // also notify the responder (self) if sockets present
      if (bet.to_user_id) emitToUser(String(bet.to_user_id), 'bet_response', payload);
    } catch (e) {
      console.warn('respond: socket emit failed', e && e.message);
    }

    res.json({ success: true, status: newStatus });
  } catch (err) {
    console.error('POST /api/requests/:id/respond error', err && err.stack ? err.stack : err);
    res.status(500).json({ error: 'server' });
  }
});

/* -----------------------
   Alerts endpoints
   ----------------------- */

app.get('/api/alerts', async (req, res) => {
  try {
    let username = req.query.user;
    if (username) username = decodeURIComponent(username);
    else if (req.session && req.session.user) username = req.session.user.name;
    else return res.json({ alerts: [] });

    const cols = await all("PRAGMA table_info('alerts')");
    const hasUsername = cols.some((c) => c.name === 'username');
    const hasTime = cols.some((c) => c.name === 'time');

    if (!hasUsername || !hasTime) {
      console.warn('alerts table missing username/time column — returning empty alerts until migration completes');
      return res.json({ alerts: [] });
    }

    const rows = await all('SELECT id, username, text, time FROM alerts WHERE username = ? ORDER BY time DESC', [username]);
    const alerts = rows.map((r) => ({ id: r.id, text: r.text, time: r.time }));
    res.json({ alerts });
  } catch (err) {
    console.error('GET /api/alerts error', err && err.stack ? err.stack : err);
    res.status(500).json({ alerts: [] });
  }
});

app.post('/api/alerts/dismiss', async (req, res) => {
  try {
    const user = req.body.user || (req.session && req.session.user && req.session.user.name);
    const alertId = req.body.alertId;
    if (!user || !alertId) return res.status(400).json({ error: 'Missing fields' });
    const a = await get('SELECT id FROM alerts WHERE id = ? AND username = ?', [alertId, user]);
    if (!a) return res.status(404).json({ error: 'Not found' });
    await run('DELETE FROM alerts WHERE id = ?', [alertId]);
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/alerts/dismiss error:', err && err.stack ? err.stack : err);
    res.status(500).json({ error: 'server' });
  }
});

/* -----------------------
   Compatibility endpoints used by dashboard.html
   ----------------------- */

app.get('/api/requests', async (req, res) => {
  try {
    let username = req.query.user;
    let userRow = null;
    if (username) {
      username = decodeURIComponent(username);
      userRow = await get('SELECT id,name FROM users WHERE name = ?', [username]);
    } else if (req.session && req.session.user) {
      userRow = await get('SELECT id,name FROM users WHERE id = ?', [req.session.user.id]);
    } else {
      return res.json({ pendingRequests: [] });
    }

    if (!userRow) return res.json({ pendingRequests: [] });

    const rows = await all(
      `SELECT b.id, b.from_user_id, fu.name as from_name, fu.email as from_email, b.match_id, b.match_title as match, b.amount, b.team_supported as team, b.status, b.created_at,
              m.date as match_date,
              m.winner AS match_winner
       FROM bets b
       LEFT JOIN users fu ON fu.id = b.from_user_id
       LEFT JOIN matches m ON (m.id = b.match_id OR m.title = b.match_title)
       WHERE b.to_user_id = ? AND b.status = 'pending'
       ORDER BY b.created_at DESC`,
      [userRow.id]
    );

    const pending = rows.map((r) => ({
      id: r.id,
      from: r.from_name,
      from_user_id: r.from_user_id,
      match: r.match,
      match_date: r.match_date,
      amount: r.amount,
      team: r.team,
      status: r.status,
      time: r.created_at,
      match_winner: r.match_winner
    }));

    res.json({ pendingRequests: pending });
  } catch (err) {
    console.error('GET /api/requests error', err);
    res.status(500).json({ pendingRequests: [] });
  }
});

app.post('/api/requests', async (req, res) => {
  try {
    let fromName = req.body.from;
    let toName = req.body.to;
    let match = req.body.match;
    let amount = req.body.amount;
    let team = req.body.team;

    if (req.session && req.session.user) fromName = req.session.user.name;
    if (!fromName || !toName || !match || !amount || !team) return res.status(400).json({ error: 'Missing fields' });
    const matchRow = await get(
      'SELECT winner FROM matches WHERE title = ?',
      [match]
    );
    if (matchRow && matchRow.winner) {
      return res.status(400).json({
        error: 'Bet not allowed. Match has been completed.'
      });
    }

    // find toUserId
    const toUserRow = await get('SELECT id,name FROM users WHERE name = ?', [toName]);
    if (!toUserRow) return res.status(404).json({ error: 'To-user not found' });

    const fromUserRow = await get('SELECT id,name FROM users WHERE name = ?', [fromName]);

    const result = await run(
      `INSERT INTO bets (from_user_id, to_user_id, match_id, match_title, amount, team_supported, status)
       VALUES (?, ?, ?, ?, ?, ?, 'pending')`, [
         fromUserRow ? fromUserRow.id : null,
         toUserRow.id,
         null,
         match,
         amount,
         team
       ]
    );
    const id = result.lastID || result.id;
    const bet = await get('SELECT * FROM bets WHERE id = ?', [id]);

    // insert alert and emit request
    try {
      const payload = {
        id: 'req_' + id,
        betId: id,
        fromUserId: fromUserRow ? fromUserRow.id : null,
        fromName: fromName,
        toUserId: toUserRow.id,
        toName: toUserRow.name,
        match,
        amount,
        team,
        status: 'pending',
        time: new Date().toISOString()
      };
      const alertId = 'a_' + Date.now() + Math.floor(Math.random() * 999);
      await run('INSERT OR REPLACE INTO alerts (id, username, text, time) VALUES (?,?,?,?)', [
        alertId,
        toUserRow.name,
        `${fromName} requested a bet of ${amount} on ${team} (${match})`,
        payload.time
      ]);
      emitToUser({ id: toUserRow.id, name: toUserRow.name }, 'bet_request', payload);
    } catch (e) {
      console.warn('create request alert/emit failed', e && e.message);
    }

    res.json({ success: true, id });
  } catch (err) {
    console.error('POST /api/requests error:', err && err.stack ? err.stack : err);
    res.status(500).json({ error: 'server' });
  }
});

/* -----------------------
   Start server
   ----------------------- */
server.listen(PORT, () => {
  console.log(`Bidibet Server running on port ${PORT}`);
  console.log(`Open locally: http://localhost:${PORT}`);
  console.log('If using ngrok: run with NODE_ENV=production or set USE_SECURE_COOKIE=true');
});
