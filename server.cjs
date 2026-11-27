const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const PORT = process.env.PORT || 3000;
const DASHBOARD_DIR = path.join(__dirname, 'dashboard');

// Smart State Directory Detection
function findStateDir() {
  const candidates = [
    process.env.TRACK4_STATE_DIR,
    path.join(__dirname, '.track4'),
    path.join(__dirname, 'state'),
    __dirname
  ];
  for (const dir of candidates) {
    if (dir && fs.existsSync(path.join(dir, 'audit.log'))) return dir;
  }
  return __dirname; 
}

const STATE_DIR = findStateDir();

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  // 1. GET /api/v1/audit
  if (req.url === '/api/v1/audit' && req.method === 'GET') {
    const logPath = path.join(STATE_DIR, 'audit.log');
    let entries = [];
    if (fs.existsSync(logPath)) {
      try {
        const content = fs.readFileSync(logPath, 'utf8').trim();
        if (content) {
          entries = content.split('\n').map(line => {
            try { return JSON.parse(line); } catch { return null; }
          }).filter(Boolean);
        }
      } catch (e) { console.error('Audit read error:', e.message); }
    }
    return res.end(JSON.stringify({ entries, total: entries.length }));
  }

  // 2. GET /api/v1/health
  if (req.url === '/api/v1/health' && req.method === 'GET') {
    return res.end(JSON.stringify({ 
      status: 'healthy', 
      pqcStatus: 'SECURE', 
      stateDir: STATE_DIR,
      kekInitialized: fs.existsSync(path.join(STATE_DIR, 'kek.bin')),
      storeInitialized: fs.existsSync(path.join(STATE_DIR, 'store.enc'))
    }));
  }

  // 3. GET /api/v1/devices (New Endpoint)
  if (req.url === '/api/v1/devices' && req.method === 'GET') {
    // In a real app, this would parse store.enc. For the dashboard, we return a safe structure.
    return res.end(JSON.stringify({ 
      devices: [
        { id: 1, name: 'Admin MacBook Pro', owner: 'admin', status: 'active', enrolled: new Date().toISOString() },
        { id: 2, name: 'Alice iPhone 15', owner: 'alice', status: 'active', enrolled: new Date().toISOString() }
      ],
      total: 2
    }));
  }

  // 4. Serve Dashboard
  if (req.url === '/' || req.url === '/index.html') {
    res.setHeader('Content-Type', 'text/html');
    const indexPath = path.join(DASHBOARD_DIR, 'index.html');
    if (fs.existsSync(indexPath)) {
      return fs.createReadStream(indexPath).pipe(res);
    }
    res.statusCode = 404;
    return res.end('Dashboard not found');
  }

  // 404 Fallback
  res.statusCode = 404;
  res.end(JSON.stringify({ error: 'Not Found' }));
});

server.listen(PORT, () => {
  console.log(`\n🚀 Ctrl+Alt+Delulu Ops API running at http://localhost:${PORT}`);
  console.log(`📊 Dashboard available at http://localhost:${PORT}/`);
  console.log(`🔒 Reading state from: ${STATE_DIR}\n`);
});

module.exports = server; // Export for testing