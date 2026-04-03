// ============================================================
// FTP Echo — Backend Server
// Node.js + Express + basic-ftp + Supabase + WebSockets
// ============================================================

'use strict';

require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const multer     = require('multer');
const { WebSocketServer } = require('ws');
const http       = require('http');
const ftp        = require('basic-ftp');
const { createClient } = require('@supabase/supabase-js');
const crypto     = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path       = require('path');
const rateLimit  = require('express-rate-limit');

// ============================================================
// CONFIG
// ============================================================
const PORT            = process.env.PORT || 3001;
const FRONTEND_URL    = process.env.FRONTEND_URL || 'http://localhost:3000';
const ENCRYPTION_KEY  = process.env.ENCRYPTION_KEY || 'fallback-dev-key-change-in-prod!!';
const SUPABASE_URL    = process.env.SUPABASE_URL;
const SUPABASE_KEY    = process.env.SUPABASE_SERVICE_KEY;

// ============================================================
// SUPABASE CLIENT
// ============================================================
const supabase = SUPABASE_URL && SUPABASE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_KEY)
  : null;

// ============================================================
// EXPRESS APP
// ============================================================
const app    = express();
const server = http.createServer(app);

// Security headers
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// CORS — only allow your frontend
app.use(cors({
  origin: [FRONTEND_URL, 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// File upload handler (memory storage for FTP upload)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 }, // 500MB max
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: { error: 'Too many requests, please try again later.' },
});
app.use(limiter);

// ============================================================
// ENCRYPTION HELPERS
// Encrypt FTP passwords before storing in Supabase
// ============================================================
const ALGO = 'aes-256-gcm';
const KEY  = crypto.scryptSync(ENCRYPTION_KEY, 'ftpecho-salt', 32);

function encrypt(text) {
  const iv  = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
  const [ivHex, tagHex, encrypted] = text.split(':');
  const iv  = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGO, KEY, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ============================================================
// AUTH MIDDLEWARE
// Verify Supabase JWT on protected routes
// ============================================================
async function requireAuth(req, res, next) {
  // Skip auth in development
  if (process.env.NODE_ENV === 'development') {
    req.userId = 'dev-user';
    return next();
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization token' });
  }

  const token = authHeader.split(' ')[1];

  try {
    if (!supabase) throw new Error('Supabase not configured');
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) throw new Error('Invalid token');
    req.userId = user.id;
    req.user   = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ============================================================
// FTP CONNECTION POOL
// Keeps active FTP clients alive per session
// ============================================================
const ftpPool = new Map(); // sessionId -> { client, lastUsed, config }

// Clean up idle connections every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of ftpPool.entries()) {
    if (now - entry.lastUsed > 10 * 60 * 1000) { // 10 min idle
      try { entry.client.close(); } catch {}
      ftpPool.delete(id);
      console.log(`[FTP] Closed idle connection: ${id}`);
    }
  }
}, 5 * 60 * 1000);

async function getFtpClient(sessionId, config) {
  // Return existing live connection
  if (ftpPool.has(sessionId)) {
    const entry = ftpPool.get(sessionId);
    entry.lastUsed = Date.now();
    // Check if still alive
    try {
      await entry.client.pwd();
      return entry.client;
    } catch {
      // Connection dropped — remove and reconnect
      ftpPool.delete(sessionId);
    }
  }

  // Create new connection
  const client = new ftp.Client(30000); // 30s timeout
  client.ftp.verbose = process.env.NODE_ENV === 'development';

  await client.access({
    host:     config.host,
    port:     parseInt(config.port) || 21,
    user:     config.username,
    password: config.password,
    secure:   config.protocol === 'FTPS',
    secureOptions: { rejectUnauthorized: false },
  });

  ftpPool.set(sessionId, {
    client,
    lastUsed: Date.now(),
    config,
  });

  console.log(`[FTP] New connection: ${config.host} (${sessionId})`);
  return client;
}

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/health', (req, res) => {
  res.json({
    status:  'ok',
    version: '1.0.0',
    uptime:  process.uptime(),
    connections: ftpPool.size,
  });
});

// ============================================================
// FTP ROUTES
// ============================================================

// POST /ftp/connect — test and establish connection
app.post('/ftp/connect', requireAuth, async (req, res) => {
  const { host, port, username, password, protocol, remotePath } = req.body;

  if (!host || !username || !password) {
    return res.status(400).json({ error: 'host, username and password are required' });
  }

  const sessionId = `${req.userId}-${host}`;

  try {
    // Close any existing connection first
    if (ftpPool.has(sessionId)) {
      try { ftpPool.get(sessionId).client.close(); } catch {}
      ftpPool.delete(sessionId);
    }

    const client = await getFtpClient(sessionId, { host, port, username, password, protocol });

    // Navigate to remote path if specified
    const startPath = remotePath || '/';
    await client.cd(startPath);
    const pwd = await client.pwd();

    // List initial directory
    const list = await client.list(pwd);
    const files = list.map(f => ({
      name:     f.name,
      type:     f.type === 2 ? 'folder' : 'file',
      size:     f.size,
      modified: f.modifiedAt,
    }));

    // Optionally save connection to Supabase
    if (supabase && req.body.save) {
      await supabase.from('connections').upsert({
        user_id:     req.userId,
        host,
        port:        port || 21,
        username,
        password:    encrypt(password),
        protocol:    protocol || 'FTP',
        remote_path: remotePath || '/',
        name:        req.body.name || host,
        updated_at:  new Date().toISOString(),
      }, { onConflict: 'user_id,host,username' });
    }

    res.json({
      success: true,
      sessionId,
      pwd,
      files,
    });
  } catch (err) {
    console.error('[FTP] Connect error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// POST /ftp/disconnect — close connection
app.post('/ftp/disconnect', requireAuth, async (req, res) => {
  const { sessionId } = req.body;
  if (ftpPool.has(sessionId)) {
    try { ftpPool.get(sessionId).client.close(); } catch {}
    ftpPool.delete(sessionId);
  }
  res.json({ success: true });
});

// GET /ftp/list — list files in directory
app.get('/ftp/list', requireAuth, async (req, res) => {
  const { sessionId, path: dirPath = '/' } = req.query;

  if (!sessionId || !ftpPool.has(sessionId)) {
    return res.status(401).json({ error: 'No active FTP session. Please reconnect.' });
  }

  try {
    const entry  = ftpPool.get(sessionId);
    const client = await getFtpClient(sessionId, entry.config);
    await client.cd(dirPath);
    const pwd  = await client.pwd();
    const list = await client.list(pwd);

    const files = list
      .filter(f => f.name !== '.' && f.name !== '..')
      .map(f => ({
        name:     f.name,
        type:     f.type === 2 ? 'folder' : 'file',
        size:     f.size,
        modified: f.modifiedAt,
        path:     pwd.endsWith('/') ? pwd + f.name : pwd + '/' + f.name,
      }))
      .sort((a, b) => {
        // Folders first, then alphabetical
        if (a.type !== b.type) return a.type === 'folder' ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

    res.json({ success: true, pwd, files });
  } catch (err) {
    console.error('[FTP] List error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /ftp/read — read file contents for editor
app.get('/ftp/read', requireAuth, async (req, res) => {
  const { sessionId, filePath } = req.query;

  if (!sessionId || !ftpPool.has(sessionId)) {
    return res.status(401).json({ error: 'No active FTP session' });
  }

  if (!filePath) {
    return res.status(400).json({ error: 'filePath is required' });
  }

  try {
    const entry  = ftpPool.get(sessionId);
    const client = await getFtpClient(sessionId, entry.config);

    // Download file to memory buffer
    const chunks = [];
    const stream = require('stream');
    const writable = new stream.Writable({
      write(chunk, encoding, callback) {
        chunks.push(chunk);
        callback();
      }
    });

    await client.downloadTo(writable, filePath);
    const content = Buffer.concat(chunks).toString('utf8');

    res.json({
      success: true,
      path:    filePath,
      content,
      size:    Buffer.byteLength(content, 'utf8'),
    });
  } catch (err) {
    console.error('[FTP] Read error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /ftp/write — save file contents from editor back to server
app.post('/ftp/write', requireAuth, async (req, res) => {
  const { sessionId, filePath, content } = req.body;

  if (!sessionId || !ftpPool.has(sessionId)) {
    return res.status(401).json({ error: 'No active FTP session' });
  }

  if (!filePath || content === undefined) {
    return res.status(400).json({ error: 'filePath and content are required' });
  }

  try {
    const entry  = ftpPool.get(sessionId);
    const client = await getFtpClient(sessionId, entry.config);

    const stream = require('stream');
    const readable = stream.Readable.from([content]);
    await client.uploadFrom(readable, filePath);

    res.json({
      success: true,
      path:    filePath,
      size:    Buffer.byteLength(content, 'utf8'),
      savedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error('[FTP] Write error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /ftp/upload — upload file(s) from browser to FTP server
app.post('/ftp/upload', requireAuth, upload.array('files'), async (req, res) => {
  const { sessionId, remotePath = '/' } = req.body;

  if (!sessionId || !ftpPool.has(sessionId)) {
    return res.status(401).json({ error: 'No active FTP session' });
  }

  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files provided' });
  }

  try {
    const entry   = ftpPool.get(sessionId);
    const client  = await getFtpClient(sessionId, entry.config);
    const results = [];

    for (const file of req.files) {
      const destPath = remotePath.endsWith('/')
        ? remotePath + file.originalname
        : remotePath + '/' + file.originalname;

      const stream = require('stream');
      const readable = stream.Readable.from([file.buffer]);
      await client.uploadFrom(readable, destPath);

      results.push({
        name:     file.originalname,
        size:     file.size,
        path:     destPath,
        uploaded: true,
      });

      console.log(`[FTP] Uploaded: ${destPath} (${file.size} bytes)`);
    }

    res.json({ success: true, uploaded: results });
  } catch (err) {
    console.error('[FTP] Upload error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /ftp/download — download file from FTP to browser
app.get('/ftp/download', requireAuth, async (req, res) => {
  const { sessionId, filePath } = req.query;

  if (!sessionId || !ftpPool.has(sessionId)) {
    return res.status(401).json({ error: 'No active FTP session' });
  }

  try {
    const entry  = ftpPool.get(sessionId);
    const client = await getFtpClient(sessionId, entry.config);

    const fileName = path.basename(filePath);
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.setHeader('Content-Type', 'application/octet-stream');

    const chunks = [];
    const stream = require('stream');
    const writable = new stream.Writable({
      write(chunk, encoding, callback) {
        chunks.push(chunk);
        callback();
      }
    });

    await client.downloadTo(writable, filePath);
    const buffer = Buffer.concat(chunks);
    res.setHeader('Content-Length', buffer.length);
    res.send(buffer);
  } catch (err) {
    console.error('[FTP] Download error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /ftp/rename — rename or move a file
app.post('/ftp/rename', requireAuth, async (req, res) => {
  const { sessionId, fromPath, toPath } = req.body;

  if (!sessionId || !ftpPool.has(sessionId)) {
    return res.status(401).json({ error: 'No active FTP session' });
  }

  try {
    const entry  = ftpPool.get(sessionId);
    const client = await getFtpClient(sessionId, entry.config);
    await client.rename(fromPath, toPath);
    res.json({ success: true, from: fromPath, to: toPath });
  } catch (err) {
    console.error('[FTP] Rename error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /ftp/delete — delete a file or folder
app.delete('/ftp/delete', requireAuth, async (req, res) => {
  const { sessionId, filePath, isFolder } = req.body;

  if (!sessionId || !ftpPool.has(sessionId)) {
    return res.status(401).json({ error: 'No active FTP session' });
  }

  try {
    const entry  = ftpPool.get(sessionId);
    const client = await getFtpClient(sessionId, entry.config);

    if (isFolder) {
      await client.removeDir(filePath);
    } else {
      await client.remove(filePath);
    }

    res.json({ success: true, deleted: filePath });
  } catch (err) {
    console.error('[FTP] Delete error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /ftp/mkdir — create a new directory
app.post('/ftp/mkdir', requireAuth, async (req, res) => {
  const { sessionId, dirPath } = req.body;

  if (!sessionId || !ftpPool.has(sessionId)) {
    return res.status(401).json({ error: 'No active FTP session' });
  }

  try {
    const entry  = ftpPool.get(sessionId);
    const client = await getFtpClient(sessionId, entry.config);
    await client.ensureDir(dirPath);
    res.json({ success: true, created: dirPath });
  } catch (err) {
    console.error('[FTP] Mkdir error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// CONNECTIONS ROUTES (saved servers)
// ============================================================

// GET /connections — list all saved connections for user
app.get('/connections', requireAuth, async (req, res) => {
  if (!supabase) return res.json({ connections: [] });

  try {
    const { data, error } = await supabase
      .from('connections')
      .select('id, name, host, port, username, protocol, remote_path, created_at')
      .eq('user_id', req.userId)
      .order('updated_at', { ascending: false });

    if (error) throw error;
    res.json({ connections: data || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /connections/:id — delete a saved connection
app.delete('/connections/:id', requireAuth, async (req, res) => {
  if (!supabase) return res.json({ success: true });

  try {
    const { error } = await supabase
      .from('connections')
      .delete()
      .eq('id', req.params.id)
      .eq('user_id', req.userId);

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// GITHUB OAUTH ROUTES
// ============================================================

// GET /github/auth — redirect to GitHub OAuth
app.get('/github/auth', requireAuth, (req, res) => {
  const params = new URLSearchParams({
    client_id:    process.env.GITHUB_CLIENT_ID,
    redirect_uri: process.env.GITHUB_CALLBACK_URL,
    scope:        'repo user:email',
    state:        req.userId,
  });
  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

// GET /github/callback — handle OAuth callback from GitHub
app.get('/github/callback', async (req, res) => {
  const { code, state: userId } = req.query;

  if (!code) {
    return res.redirect(`${FRONTEND_URL}/app?error=github_denied`);
  }

  try {
    // Exchange code for access token
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        client_id:     process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
      }),
    });

    const tokenData = await tokenRes.json();
    if (tokenData.error) throw new Error(tokenData.error_description);

    const accessToken = tokenData.access_token;

    // Get GitHub user info
    const userRes = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const ghUser = await userRes.json();

    // Store token in Supabase (encrypted)
    if (supabase) {
      await supabase.from('github_tokens').upsert({
        user_id:      userId,
        github_login: ghUser.login,
        github_id:    ghUser.id,
        access_token: encrypt(accessToken),
        updated_at:   new Date().toISOString(),
      }, { onConflict: 'user_id' });
    }

    res.redirect(`${FRONTEND_URL}/app?github=connected&login=${ghUser.login}`);
  } catch (err) {
    console.error('[GitHub] OAuth error:', err.message);
    res.redirect(`${FRONTEND_URL}/app?error=github_failed`);
  }
});

// GET /github/repos — list user's GitHub repositories
app.get('/github/repos', requireAuth, async (req, res) => {
  try {
    const token = await getGithubToken(req.userId);
    const reposRes = await fetch('https://api.github.com/user/repos?sort=updated&per_page=50', {
      headers: { Authorization: `Bearer ${token}` },
    });
    const repos = await reposRes.json();

    res.json({
      repos: repos.map(r => ({
        id:          r.id,
        name:        r.name,
        full_name:   r.full_name,
        description: r.description,
        private:     r.private,
        language:    r.language,
        updated_at:  r.updated_at,
        default_branch: r.default_branch,
        clone_url:   r.clone_url,
      }))
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// GET /github/branches — list branches for a repo
app.get('/github/branches', requireAuth, async (req, res) => {
  const { repo } = req.query;
  try {
    const token = await getGithubToken(req.userId);
    const branchRes = await fetch(`https://api.github.com/repos/${repo}/branches`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const branches = await branchRes.json();
    res.json({ branches: branches.map(b => b.name) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

async function getGithubToken(userId) {
  if (!supabase) throw new Error('Supabase not configured');
  const { data, error } = await supabase
    .from('github_tokens')
    .select('access_token')
    .eq('user_id', userId)
    .single();
  if (error || !data) throw new Error('GitHub not connected. Please authorize first.');
  return decrypt(data.access_token);
}

// ============================================================
// WEBSOCKET — Live terminal streaming
// Each client gets a real-time log of FTP operations
// ============================================================
const wss = new WebSocketServer({ server, path: '/terminal' });

wss.on('connection', (ws, req) => {
  const sessionId = new URL(req.url, 'http://localhost').searchParams.get('session');
  console.log(`[WS] Terminal connected: ${sessionId}`);

  ws.send(JSON.stringify({
    type: 'connected',
    message: 'Terminal ready',
  }));

  ws.on('message', async (data) => {
    try {
      const { command, sessionId: sid } = JSON.parse(data);

      if (!ftpPool.has(sid)) {
        ws.send(JSON.stringify({ type: 'error', message: 'No active FTP session' }));
        return;
      }

      const entry  = ftpPool.get(sid);
      const client = await getFtpClient(sid, entry.config);

      // Handle basic terminal commands
      let result = '';
      const parts = command.trim().split(/\s+/);
      const cmd   = parts[0].toLowerCase();

      switch (cmd) {
        case 'ls':
        case 'dir': {
          const list = await client.list();
          result = list.map(f =>
            `${f.type === 2 ? 'd' : '-'}rw-r--r-- ${String(f.size || 0).padStart(10)} ${f.name}`
          ).join('\n');
          break;
        }
        case 'pwd': {
          result = await client.pwd();
          break;
        }
        case 'cd': {
          const target = parts[1] || '/';
          await client.cd(target);
          result = `Changed to ${await client.pwd()}`;
          break;
        }
        case 'rm': {
          if (!parts[1]) { result = 'Usage: rm <filename>'; break; }
          await client.remove(parts[1]);
          result = `Deleted: ${parts[1]}`;
          break;
        }
        case 'mkdir': {
          if (!parts[1]) { result = 'Usage: mkdir <dirname>'; break; }
          await client.ensureDir(parts[1]);
          result = `Created: ${parts[1]}`;
          break;
        }
        case 'mv':
        case 'rename': {
          if (!parts[1] || !parts[2]) { result = `Usage: ${cmd} <from> <to>`; break; }
          await client.rename(parts[1], parts[2]);
          result = `Renamed: ${parts[1]} → ${parts[2]}`;
          break;
        }
        case 'help': {
          result = [
            'Available commands:',
            '  ls / dir     — list files',
            '  pwd          — current directory',
            '  cd <path>    — change directory',
            '  rm <file>    — delete file',
            '  mkdir <dir>  — create directory',
            '  mv <a> <b>   — rename/move file',
            '  help         — show this help',
          ].join('\n');
          break;
        }
        default:
          result = `Unknown command: ${cmd}. Type 'help' for available commands.`;
      }

      ws.send(JSON.stringify({ type: 'output', message: result }));
    } catch (err) {
      ws.send(JSON.stringify({ type: 'error', message: err.message }));
    }
  });

  ws.on('close', () => {
    console.log(`[WS] Terminal disconnected: ${sessionId}`);
  });
});

// ============================================================
// ERROR HANDLER
// ============================================================
app.use((err, req, res, next) => {
  console.error('[Server] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` });
});

// ============================================================
// START SERVER
// ============================================================
server.listen(PORT, () => {
  console.log('');
  console.log('  ███████╗████████╗██████╗     ███████╗ ██████╗██╗  ██╗ ██████╗ ');
  console.log('  ██╔════╝╚══██╔══╝██╔══██╗    ██╔════╝██╔════╝██║  ██║██╔═══██╗');
  console.log('  █████╗     ██║   ██████╔╝    █████╗  ██║     ███████║██║   ██║');
  console.log('  ██╔══╝     ██║   ██╔═══╝     ██╔══╝  ██║     ██╔══██║██║   ██║');
  console.log('  ██║        ██║   ██║         ███████╗╚██████╗██║  ██║╚██████╔╝');
  console.log('  ╚═╝        ╚═╝   ╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ');
  console.log('');
  console.log(`  Server running on port ${PORT}`);
  console.log(`  Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`  Frontend: ${FRONTEND_URL}`);
  console.log(`  Supabase: ${supabase ? 'connected' : 'not configured'}`);
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[Server] Shutting down...');
  for (const [, entry] of ftpPool.entries()) {
    try { entry.client.close(); } catch {}
  }
  server.close(() => process.exit(0));
});

module.exports = { app, server };
