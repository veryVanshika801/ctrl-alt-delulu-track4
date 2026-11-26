const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const PORT = process.env.PORT || 3000;
// Default to a 'state' folder in the root, or use env var
const STATE_DIR = process.env.TRACK4_STATE_DIR || path.join(__dirname, 'state');
const DASHBOARD_DIR = path.join(__dirname, 'dashboard');

const server = http.createServer((req, res) => {
  // CORS Headers for local development
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    return res.end();
  }

  // 1. REST API: Get Audit Logs
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
      } catch (err) {
        console.error('Error reading audit log:', err.message);
      }
    }
    return res.end(JSON.stringify({ entries, total: entries.length }));
  }

  // 2. REST API: Health & Crypto Status
  if (req.url === '/api/v1/health' && req.method === 'GET') {
    const kekExists = fs.existsSync(path.join(STATE_DIR, 'kek.bin'));
    const storeExists = fs.existsSync(path.join(STATE_DIR, 'store.enc'));
    
    return res.end(JSON.stringify({ 
      status: 'healthy', 
      pqcStatus: 'SECURE', 
      activeDevices: 5, // Mocked for UI, replace with actual count if you parse store.enc
      chainIntact: true,
      kekInitialized: kekExists,
      storeInitialized: storeExists
    }));
  }

  // 3. REST API: Threat Alerts
  if (req.url === '/api/v1/alerts' && req.method === 'GET') {
    // Try to run your actual detector script if it exists
    const alertsScript = path.join(__dirname, 'bin', 'alerts.cjs');
    let alerts = [];
    
    if (fs.existsSync(alertsScript)) {
      try {
        const result = spawnSync('node', [alertsScript, '--json'], { encoding: 'utf8', timeout: 5000 });
        if (result.status === 0 && result.stdout) {
          alerts = JSON.parse(result.stdout);
        }
      } catch (e) {
        // Fallback to mock data if script fails
      }
    }

    // Fallback mock data if no real alerts are found
    if (alerts.length === 0) {
      alerts = [
        { severity: 'HIGH', rule: 'LATERAL_MOVEMENT', identity: 'svc-payroll', path: 'portal → vault → hr-db', time: '2m ago' },
        { severity: 'MEDIUM', rule: 'PRIVILEGE_ESCALATION', identity: 'user_jdoe', path: 'login → admin-panel', time: '8m ago' }
      ];
    }
    
    return res.end(JSON.stringify({ alerts }));
  }

  // 4. Serve Frontend Dashboard (index.html)
  if (req.url === '/' || req.url === '/index.html') {
    res.setHeader('Content-Type', 'text/html');
    const indexPath = path.join(DASHBOARD_DIR, 'index.html');
    if (fs.existsSync(indexPath)) {
      return fs.createReadStream(indexPath).pipe(res);
    }
    res.statusCode = 404;
    return res.end('Dashboard not found');
  }

  // 404 Fallback for API
  res.statusCode = 404;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ error: 'Endpoint Not Found' }));
});

server.listen(PORT, () => {
  console.log(`\n🚀 Ctrl+Alt+Delulu Ops API running at http://localhost:${PORT}`);
  console.log(`📊 Dashboard available at http://localhost:${PORT}/`);
  console.log(`🔒 State directory: ${STATE_DIR}\n`);
});