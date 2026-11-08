const express = require('express'), fs = require('fs'), path = require('path'), crypto = require('crypto'),
  bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), multer = require('multer');

const app = express(),
  PORT = process.env.PORT || 3000,
  SECRET = process.env.JWT_SECRET || 'local-dev-secret-change-before-public-launch',
  ROOT = __dirname,
  UP = path.join(ROOT, 'uploads'),
  DB = path.join(ROOT, 'data/db.json');

/* =====================================================================
   ADMIN SOZLAMASI  ←←←  SHU YERNI O'ZGARTIRING
   Pastdagi ro'yxatga o'zingizning username'ingizni yozing (kichik harflarda).
   Bir nechta admin bo'lsa vergul bilan ajrating: ['ali', 'vali']
   (Yoki serverni ishga tushirganda: ADMINS=ali,vali node server.js)
   ===================================================================== */
const ADMINS = (process.env.ADMINS || 'mrbeast')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const VERIFY_MIN_SUBS = 1000;   // verified badge uchun minimal obunachi
const ONLINE_MS = 70 * 1000;    // oxirgi 70 soniyada faol bo'lsa — online

fs.mkdirSync(UP, { recursive: true });
fs.mkdirSync(path.dirname(DB), { recursive: true });

const blank = () => ({ users: [], videos: [], comments: [], likes: [], subscriptions: [], history: [], saved: [] });
let db;
try { db = { ...blank(), ...JSON.parse(fs.readFileSync(DB)) }; } catch { db = blank(); }

let dirty = false;
const save = () => { dirty = false; fs.writeFileSync(DB, JSON.stringify(db, null, 2)); };
// "oxirgi faollik" tez-tez o'zgargani uchun diskka har daqiqada bir marta yoziladi
setInterval(() => { if (dirty) save(); }, 60 * 1000);
process.on('SIGINT', () => { save(); process.exit(); });

const id = () => crypto.randomUUID();
const isAdmin = u => !!u && ADMINS.includes(u.username);
const isOnline = u => !!u.lastSeenAt && Date.now() - u.lastSeenAt < ONLINE_MS;
const subsOf = uid => db.subscriptions.filter(x => x.channelId === uid).length;

// Ommaga ko'rinadigan ma'lumot (rank bu yerda yo'q — cho'ktirish/tavsiya yashirin qoladi)
const safe = u => ({ id: u.id, username: u.username, channelName: u.channelName, about: u.about || '', verified: !!u.verified });
// Faqat o'ziga ko'rinadigan ma'lumot
const me = u => ({ ...safe(u), isAdmin: isAdmin(u) });

/* ---------- Autentifikatsiya ---------- */
const getUser = req => {
  try {
    const t = (req.headers.authorization || '').replace(/^Bearer /, '');
    return t ? db.users.find(u => u.id === jwt.verify(t, SECRET).id) : undefined;
  } catch { return undefined; }
};
const touch = u => { u.lastSeenAt = Date.now(); dirty = true; };

const auth = (req, res, next) => {
  const u = getUser(req);
  if (!u) return res.status(401).json({ error: 'Avval akkauntga kiring.' });
  if (u.banned) return res.status(403).json({ error: 'Akkauntingiz bloklangan.' });
  touch(u); req.user = u; next();
};
const optional = (req, res, next) => {
  const u = getUser(req);
  if (u && !u.banned) { touch(u); req.user = u; }
  next();
};
const adminOnly = (req, res, next) =>
  auth(req, res, () => isAdmin(req.user) ? next() : res.status(403).json({ error: 'Faqat adminlar uchun.' }));

const pub = (v, viewer) => ({
  ...v,
  owner: safe(db.users.find(u => u.id === v.userId) || { username: 'unknown', channelName: 'Noma’lum kanal' }),
  likeCount: db.likes.filter(x => x.videoId === v.id).length,
  commentCount: db.comments.filter(x => x.videoId === v.id).length,
  liked: !!viewer && db.likes.some(x => x.videoId === v.id && x.userId === viewer.id)
});

const removeVideo = v => {
  db.videos = db.videos.filter(x => x.id !== v.id);
  db.comments = db.comments.filter(x => x.videoId !== v.id);
  db.likes = db.likes.filter(x => x.videoId !== v.id);
  db.history = db.history.filter(x => x.videoId !== v.id);
  db.saved = db.saved.filter(x => x.videoId !== v.id);
  if (v.filename) { try { fs.unlinkSync(path.join(UP, v.filename)); } catch {} }
};

app.use(express.json());
app.use('/uploads', express.static(UP));
app.use(express.static(path.join(ROOT, 'public')));

const storage = multer.diskStorage({
  destination: UP,
  filename: (r, f, cb) => cb(null, Date.now() + '-' + crypto.randomBytes(5).toString('hex') + path.extname(f.originalname).toLowerCase())
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 }, fileFilter: (r, f, cb) => cb(null, f.mimetype.startsWith('video/')) });

/* ---------- Ro'yxatdan o'tish / kirish ---------- */
app.post('/api/register', async (req, res) => {
  let username = String(req.body.username || '').trim().toLowerCase(), password = String(req.body.password || '');
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'Username 3–20 belgi bo‘lsin.' });
  if (password.length < 8) return res.status(400).json({ error: 'Parol kamida 8 belgi bo‘lsin.' });
  if (db.users.some(u => u.username === username)) return res.status(409).json({ error: 'Username band.' });
  let u = {
    id: id(), username, channelName: String(req.body.channelName || username).slice(0, 40), about: '',
    password: await bcrypt.hash(password, 12), createdAt: new Date().toISOString(), lastSeenAt: Date.now()
  };
  db.users.push(u); save();
  res.json({ token: jwt.sign({ id: u.id }, SECRET, { expiresIn: '7d' }), user: me(u) });
});

app.post('/api/login', async (req, res) => {
  let u = db.users.find(x => x.username === String(req.body.username || '').toLowerCase());
  if (!u || !await bcrypt.compare(String(req.body.password || ''), u.password))
    return res.status(401).json({ error: 'Login yoki parol noto‘g‘ri.' });
  if (u.banned) return res.status(403).json({ error: 'Akkauntingiz bloklangan.' });
  touch(u);
  res.json({ token: jwt.sign({ id: u.id }, SECRET, { expiresIn: '7d' }), user: me(u) });
});

app.get('/api/me', auth, (req, res) => res.json(me(req.user)));

// Online holatni yangilash (sayt har 30 soniyada yuboradi)
app.post('/api/ping', auth, (req, res) => res.json({ ok: true }));

/* ---------- Videolar ---------- */
app.get('/api/videos', optional, (req, res) => {
  let q = String(req.query.q || '').toLowerCase(), c = String(req.query.category || '');
  const owner = v => db.users.find(u => u.id === v.userId);
  // tavsiyadagi kanal +1 (tepada), cho'ktirilgan kanal -1 (eng pastda)
  const weight = v => { const o = owner(v); return o && o.rank === 'boost' ? 1 : o && o.rank === 'demote' ? -1 : 0; };
  res.json(
    db.videos
      .filter(v => { const o = owner(v); return !(o && o.banned); })
      .filter(v => (!q || (v.title + ' ' + v.description + ' ' + v.category).toLowerCase().includes(q)) &&
                   (!c || c === 'Barchasi' || v.category === c))
      .sort((a, b) => weight(b) - weight(a) || b.createdAt.localeCompare(a.createdAt))
      .map(v => pub(v, req.user))
  );
});

app.get('/api/videos/:id', optional, (req, res) => {
  let v = db.videos.find(x => x.id === req.params.id);
  if (!v) return res.status(404).json({ error: 'Video topilmadi.' });
  v.views++;
  if (req.user) {
    db.history = db.history.filter(x => !(x.userId === req.user.id && x.videoId === v.id));
    db.history.unshift({ userId: req.user.id, videoId: v.id });
  }
  save();
  res.json(pub(v, req.user));
});

app.post('/api/videos', auth, upload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Video fayl tanlanmadi.' });
  let title = String(req.body.title || '').trim();
  if (!title) { fs.unlinkSync(req.file.path); return res.status(400).json({ error: 'Video nomini yozing.' }); }
  let v = {
    id: id(), userId: req.user.id, title: title.slice(0, 100),
    description: String(req.body.description || '').slice(0, 2000),
    category: String(req.body.category || 'Boshqa'),
    url: '/uploads/' + req.file.filename, filename: req.file.filename, views: 0, createdAt: new Date().toISOString()
  };
  db.videos.push(v); save();
  res.json(pub(v, req.user));
});

app.post('/api/videos/:id/like', auth, (req, res) => {
  let exists = db.likes.some(x => x.userId === req.user.id && x.videoId === req.params.id);
  db.likes = db.likes.filter(x => !(x.userId === req.user.id && x.videoId === req.params.id));
  if (!exists) db.likes.push({ userId: req.user.id, videoId: req.params.id });
  save();
  res.json({ liked: !exists });
});

app.get('/api/videos/:id/comments', (req, res) =>
  res.json(db.comments.filter(x => x.videoId === req.params.id).map(c => ({
    ...c, user: safe(db.users.find(u => u.id === c.userId) || { username: '?', channelName: 'Foydalanuvchi' })
  }))));

app.post('/api/videos/:id/comments', auth, (req, res) => {
  let body = String(req.body.body || '').trim();
  if (!body || body.length > 1000) return res.status(400).json({ error: 'Izoh 1–1000 belgi bo‘lsin.' });
  let c = { id: id(), videoId: req.params.id, userId: req.user.id, body, createdAt: new Date().toISOString() };
  db.comments.push(c); save();
  res.json(c);
});

/* ---------- Kanallar ---------- */
app.post('/api/channels/:id/subscribe', auth, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'O‘z kanalingizga obuna bo‘lolmaysiz.' });
  let has = db.subscriptions.some(x => x.userId === req.user.id && x.channelId === req.params.id);
  db.subscriptions = db.subscriptions.filter(x => !(x.userId === req.user.id && x.channelId === req.params.id));
  if (!has) db.subscriptions.push({ userId: req.user.id, channelId: req.params.id });
  save();
  res.json({ subscribed: !has, count: subsOf(req.params.id) });
});

app.get('/api/channels/:id', optional, (req, res) => {
  let u = db.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Kanal topilmadi.' });
  res.json({ user: safe(u), subscribers: subsOf(u.id), videos: db.videos.filter(v => v.userId === u.id).map(v => pub(v, req.user)) });
});

app.get('/api/studio', auth, (req, res) => {
  let videos = db.videos.filter(v => v.userId === req.user.id);
  res.json({ videos: videos.map(v => pub(v, req.user)), views: videos.reduce((n, v) => n + v.views, 0), subscribers: subsOf(req.user.id) });
});

app.get('/api/library', auth, (req, res) =>
  res.json({ history: db.history.filter(x => x.userId === req.user.id).map(x => db.videos.find(v => v.id === x.videoId)).filter(Boolean).map(v => pub(v, req.user)) }));

/* =====================================================================
   ADMIN YO'LLARI  (hammasi serverda adminligi tekshiriladi)
   ===================================================================== */
app.get('/api/admin/users', adminOnly, (req, res) => {
  res.json(db.users.map(u => ({
    id: u.id, username: u.username, channelName: u.channelName,
    createdAt: u.createdAt || null, lastSeenAt: u.lastSeenAt || null,
    online: isOnline(u), banned: !!u.banned, isAdmin: isAdmin(u),
    verified: !!u.verified, rank: u.rank || 'normal',
    videoCount: db.videos.filter(v => v.userId === u.id).length,
    subscribers: subsOf(u.id)
  })));
});

app.get('/api/admin/videos', adminOnly, (req, res) =>
  res.json([...db.videos].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(v => pub(v, null))));

app.post('/api/admin/users/:id/ban', adminOnly, (req, res) => {
  const u = db.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Foydalanuvchi topilmadi.' });
  if (isAdmin(u)) return res.status(400).json({ error: 'Adminni bloklab bo‘lmaydi.' });
  u.banned = !!req.body.banned; save();
  res.json({ banned: u.banned });
});

app.delete('/api/admin/users/:id', adminOnly, (req, res) => {
  const u = db.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Foydalanuvchi topilmadi.' });
  if (isAdmin(u)) return res.status(400).json({ error: 'Adminni o‘chirib bo‘lmaydi.' });
  db.videos.filter(v => v.userId === u.id).forEach(removeVideo);
  db.users = db.users.filter(x => x.id !== u.id);
  db.comments = db.comments.filter(x => x.userId !== u.id);
  db.likes = db.likes.filter(x => x.userId !== u.id);
  db.subscriptions = db.subscriptions.filter(x => x.userId !== u.id && x.channelId !== u.id);
  db.history = db.history.filter(x => x.userId !== u.id);
  db.saved = db.saved.filter(x => x.userId !== u.id);
  save();
  res.json({ deleted: true });
});

app.delete('/api/admin/videos/:id', adminOnly, (req, res) => {
  const v = db.videos.find(x => x.id === req.params.id);
  if (!v) return res.status(404).json({ error: 'Video topilmadi.' });
  removeVideo(v); save();
  res.json({ deleted: true });
});

// Verified badge: faqat 1000+ obunachisi bor kanalga beriladi
app.post('/api/admin/users/:id/verify', adminOnly, (req, res) => {
  const u = db.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Foydalanuvchi topilmadi.' });
  const want = !!req.body.verified;
  if (want && !isAdmin(u) && subsOf(u.id) < VERIFY_MIN_SUBS) // admin (rasmiy) kanallar uchun limit yo'q
    return res.status(400).json({ error: `Verified uchun kamida ${VERIFY_MIN_SUBS} obunachi kerak.` });
  u.verified = want; save();
  res.json({ verified: u.verified });
});

// Kanal reytingi: boost (tavsiya) / normal / demote (cho'ktirish)
app.post('/api/admin/users/:id/rank', adminOnly, (req, res) => {
  const u = db.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'Foydalanuvchi topilmadi.' });
  const rank = String(req.body.rank || '');
  if (!['boost', 'normal', 'demote'].includes(rank)) return res.status(400).json({ error: 'Noto‘g‘ri holat.' });
  u.rank = rank; save();
  res.json({ rank });
});

app.listen(PORT, () => {
  console.log('YOUTUBE PRO: http://localhost:' + PORT);
  console.log('Adminlar: ' + ADMINS.join(', '));
});