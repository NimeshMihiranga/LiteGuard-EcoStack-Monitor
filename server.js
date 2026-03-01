const express = require('express');
const session = require('express-session');
const { exec } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const pty = require('node-pty');
const multer = require('multer');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const LOGIN_USER = process.env.PANEL_USER || 'admin';
const LOGIN_PASS = process.env.PANEL_PASS || 'admin123';

const sessionMiddleware = session({
  secret: 'liteguard-vpsui-secret-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
});

const upload = multer({ dest: '/tmp/uploads/' });

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(sessionMiddleware);

function requireAuth(req, res, next) {
  if (req.session && req.session.loggedIn) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

function run(cmd, timeout = 15000) {
  return new Promise((resolve) => {
    exec(cmd, { timeout }, (err, stdout, stderr) => {
      resolve({ err, stdout: stdout?.trim() || '', stderr: stderr?.trim() || '' });
    });
  });
}

app.get('/', (req, res) => {
  if (req.session?.loggedIn) {
    res.sendFile(path.join(__dirname, 'public', 'ui.html'));
  } else {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === LOGIN_USER && password === LOGIN_PASS) {
    req.session.loggedIn = true;
    req.session.user = username;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const cpus = os.cpus();
    let cpuUsage = 0;
    try {
      const { stdout } = await run("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1");
      cpuUsage = parseFloat(stdout) || 0;
    } catch {}
    let disk = { used: '0G', total: '0G', percent: '0%' };
    try {
      const { stdout } = await run("df -h / | awk 'NR==2{print $3,$2,$5}'");
      if (stdout) { const p = stdout.split(' '); disk = { used: p[0], total: p[1], percent: p[2] }; }
    } catch {}
    let netStats = { rx: '0', tx: '0' };
    try {
      const { stdout } = await run("cat /proc/net/dev | grep -v lo | awk 'NR>2{rx+=$2;tx+=$10}END{print rx,tx}'");
      if (stdout) { const p = stdout.split(' '); netStats = { rx: p[0], tx: p[1] }; }
    } catch {}
    res.json({
      ram_used_gb: (usedMem / 1e9).toFixed(2),
      ram_free_gb: (freeMem / 1e9).toFixed(2),
      ram_total_gb: (totalMem / 1e9).toFixed(2),
      ram_percent: ((usedMem / totalMem) * 100).toFixed(1),
      cpu_usage_percent: cpuUsage.toFixed(2),
      cpu_cores: cpus.length,
      cpu_model: cpus[0]?.model || 'Unknown',
      uptime: Math.floor(os.uptime()),
      disk,
      load_avg: os.loadavg().map(v => v.toFixed(2)),
      net: netStats
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/sysinfo', requireAuth, async (req, res) => {
  const [hostname, osInfo, kernel, ip, nodeV] = await Promise.all([
    run('hostname'),
    run("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo 'Linux'"),
    run('uname -r'),
    run("curl -s --max-time 3 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}'"),
    Promise.resolve({ stdout: process.version })
  ]);
  res.json({
    hostname: hostname.stdout || 'vps',
    os: osInfo.stdout || 'Linux',
    kernel: kernel.stdout || 'unknown',
    public_ip: ip.stdout?.trim() || 'N/A',
    node_version: nodeV.stdout,
    arch: os.arch(),
    platform: os.platform()
  });
});

app.get('/api/files', requireAuth, async (req, res) => {
  try {
    const dirPath = req.query.path || '/root';
    const safePath = path.resolve(dirPath);
    const items = fs.readdirSync(safePath, { withFileTypes: true });
    const result = items.map(item => {
      let size = 0, mtime = null;
      try {
        const stat = fs.statSync(path.join(safePath, item.name));
        size = stat.size;
        mtime = stat.mtime;
      } catch {}
      return {
        name: item.name,
        type: item.isDirectory() ? 'dir' : item.isSymbolicLink() ? 'link' : 'file',
        size,
        mtime,
        hidden: item.name.startsWith('.')
      };
    }).sort((a, b) => {
      if (a.type === 'dir' && b.type !== 'dir') return -1;
      if (a.type !== 'dir' && b.type === 'dir') return 1;
      return a.name.localeCompare(b.name);
    });
    res.json({ path: safePath, items: result });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/files/read', requireAuth, async (req, res) => {
  try {
    const filePath = path.resolve(req.query.path);
    const stat = fs.statSync(filePath);
    if (stat.size > 2 * 1024 * 1024) return res.status(413).json({ error: 'File too large (max 2MB)' });
    const content = fs.readFileSync(filePath, 'utf8');
    res.json({ content, path: filePath });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/files/write', requireAuth, async (req, res) => {
  try {
    const { filePath, content } = req.body;
    fs.writeFileSync(path.resolve(filePath), content, 'utf8');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/files/mkdir', requireAuth, async (req, res) => {
  try {
    fs.mkdirSync(path.resolve(req.body.path), { recursive: true });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/files/rename', requireAuth, async (req, res) => {
  try {
    fs.renameSync(path.resolve(req.body.from), path.resolve(req.body.to));
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/files/delete', requireAuth, async (req, res) => {
  try {
    const p = path.resolve(req.body.path);
    const stat = fs.statSync(p);
    if (stat.isDirectory()) fs.rmSync(p, { recursive: true, force: true });
    else fs.unlinkSync(p);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/files/upload', requireAuth, upload.array('files'), async (req, res) => {
  try {
    const destDir = path.resolve(req.body.path || '/root');
    for (const file of req.files) {
      fs.renameSync(file.path, path.join(destDir, file.originalname));
    }
    res.json({ success: true, count: req.files.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/files/download', requireAuth, (req, res) => {
  try {
    const filePath = path.resolve(req.query.path);
    res.download(filePath);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/pm2/list', requireAuth, async (req, res) => {
  const { stdout } = await run('pm2 jlist 2>/dev/null || echo "[]"');
  try {
    const list = JSON.parse(stdout || '[]');
    res.json(list.map(p => ({
      id: p.pm_id, name: p.name, status: p.pm2_env?.status,
      cpu: p.monit?.cpu, memory: p.monit?.memory,
      restarts: p.pm2_env?.restart_time, uptime: p.pm2_env?.pm_uptime,
      pid: p.pid, exec_mode: p.pm2_env?.exec_mode,
      script: p.pm2_env?.pm_exec_path
    })));
  } catch { res.json([]); }
});

app.post('/api/pm2/:action/:id', requireAuth, async (req, res) => {
  const { action, id } = req.params;
  if (!['start','stop','restart','delete','reload'].includes(action))
    return res.status(400).json({ error: 'Invalid action' });
  const { err, stdout } = await run(`pm2 ${action} ${id}`);
  res.json({ success: !err, output: stdout, error: err?.message });
});

app.get('/api/pm2/logs/:id', requireAuth, async (req, res) => {
  const { stdout } = await run(`pm2 logs ${req.params.id} --lines 100 --nostream 2>&1`);
  res.json({ logs: stdout || 'No logs.' });
});

app.post('/api/pm2/flush/:id', requireAuth, async (req, res) => {
  const { stdout } = await run(`pm2 flush ${req.params.id} 2>&1`);
  res.json({ success: true, output: stdout });
});

app.get('/api/firewall/status', requireAuth, async (req, res) => {
  const { stdout } = await run('ufw status verbose 2>/dev/null || echo "UFW not available"');
  const { stdout: rules } = await run('ufw status numbered 2>/dev/null || echo ""');
  res.json({ status: stdout, rules: rules });
});

app.post('/api/firewall/allow', requireAuth, async (req, res) => {
  const { port, proto } = req.body;
  const p = parseInt(port);
  if (!p || p < 1 || p > 65535) return res.status(400).json({ error: 'Invalid port' });
  const { err, stdout } = await run(`ufw allow ${p}/${proto || 'tcp'} 2>&1`);
  res.json({ success: !err, output: stdout });
});

app.post('/api/firewall/deny', requireAuth, async (req, res) => {
  const { port, proto } = req.body;
  const p = parseInt(port);
  if (!p || p < 1 || p > 65535) return res.status(400).json({ error: 'Invalid port' });
  const { err, stdout } = await run(`ufw deny ${p}/${proto || 'tcp'} 2>&1`);
  res.json({ success: !err, output: stdout });
});

app.post('/api/firewall/delete', requireAuth, async (req, res) => {
  const { rule } = req.body;
  const { err, stdout } = await run(`echo "y" | ufw delete ${rule} 2>&1`);
  res.json({ success: !err, output: stdout });
});

app.post('/api/firewall/toggle', requireAuth, async (req, res) => {
  const { enable } = req.body;
  const { stdout } = await run(`echo "y" | ufw ${enable ? 'enable' : 'disable'} 2>&1`);
  res.json({ success: true, output: stdout });
});

app.get('/api/cron/list', requireAuth, async (req, res) => {
  const { stdout } = await run('crontab -l 2>/dev/null || echo ""');
  const lines = stdout.split('\n').filter(l => l.trim() && !l.startsWith('#'));
  res.json({ raw: stdout, jobs: lines });
});

app.post('/api/cron/save', requireAuth, async (req, res) => {
  const { content } = req.body;
  const tmpFile = `/tmp/cron_${Date.now()}`;
  fs.writeFileSync(tmpFile, content + '\n');
  const { err, stdout } = await run(`crontab ${tmpFile} 2>&1`);
  fs.unlinkSync(tmpFile);
  res.json({ success: !err, output: stdout || 'Cron updated successfully' });
});

app.get('/api/users/list', requireAuth, async (req, res) => {
  const { stdout } = await run("getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1,$3,$6,$7}' | head -30");
  const { stdout: root } = await run("id root | head -1");
  const users = stdout.split('\n').filter(Boolean).map(l => {
    const p = l.split(' ');
    return { name: p[0], uid: p[1], home: p[2], shell: p[3] };
  });
  res.json({ users: [{ name: 'root', uid: '0', home: '/root', shell: '/bin/bash' }, ...users] });
});

app.post('/api/users/add', requireAuth, async (req, res) => {
  const { username, password, sudo: isSudo } = req.body;
  if (!username || !/^[a-z_][a-z0-9_-]*$/.test(username))
    return res.status(400).json({ error: 'Invalid username' });
  const { err: e1, stdout: s1 } = await run(`useradd -m -s /bin/bash ${username} 2>&1`);
  if (e1 && !s1.includes('already exists')) return res.json({ success: false, output: s1 });
  if (password) {
    await run(`echo "${username}:${password}" | chpasswd 2>&1`);
  }
  if (isSudo) await run(`usermod -aG sudo ${username} 2>&1`);
  res.json({ success: true, output: `User ${username} created` });
});

app.post('/api/users/delete', requireAuth, async (req, res) => {
  const { username } = req.body;
  if (username === 'root') return res.status(400).json({ error: 'Cannot delete root' });
  const { err, stdout } = await run(`userdel -r ${username} 2>&1`);
  res.json({ success: !err, output: stdout || `User ${username} deleted` });
});

app.post('/api/users/passwd', requireAuth, async (req, res) => {
  const { username, password } = req.body;
  const { err, stdout } = await run(`echo "${username}:${password}" | chpasswd 2>&1`);
  res.json({ success: !err, output: stdout || 'Password changed' });
});

app.get('/api/nginx/sites', requireAuth, async (req, res) => {
  const { stdout: available } = await run('ls /etc/nginx/sites-available/ 2>/dev/null || echo ""');
  const { stdout: enabled } = await run('ls /etc/nginx/sites-enabled/ 2>/dev/null || echo ""');
  const { stdout: status } = await run('systemctl is-active nginx 2>/dev/null || echo "inactive"');
  const availList = available.split('\n').filter(Boolean);
  const enabledList = enabled.split('\n').filter(Boolean);
  res.json({
    available: availList,
    enabled: enabledList,
    status: status.trim()
  });
});

app.get('/api/nginx/config/:site', requireAuth, async (req, res) => {
  const site = path.basename(req.params.site);
  const filePath = `/etc/nginx/sites-available/${site}`;
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    res.json({ content, path: filePath });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/nginx/config/:site', requireAuth, async (req, res) => {
  const site = path.basename(req.params.site);
  const filePath = `/etc/nginx/sites-available/${site}`;
  try {
    fs.writeFileSync(filePath, req.body.content);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/nginx/enable/:site', requireAuth, async (req, res) => {
  const site = path.basename(req.params.site);
  const { err, stdout } = await run(`ln -sf /etc/nginx/sites-available/${site} /etc/nginx/sites-enabled/${site} 2>&1 && nginx -t 2>&1`);
  res.json({ success: !err, output: stdout });
});

app.post('/api/nginx/disable/:site', requireAuth, async (req, res) => {
  const site = path.basename(req.params.site);
  const { err, stdout } = await run(`rm -f /etc/nginx/sites-enabled/${site} 2>&1`);
  res.json({ success: !err, output: stdout || 'Site disabled' });
});

app.post('/api/nginx/reload', requireAuth, async (req, res) => {
  const { err, stdout } = await run('nginx -t 2>&1 && systemctl reload nginx 2>&1');
  res.json({ success: !err, output: stdout });
});

app.get('/api/packages/updates', requireAuth, async (req, res) => {
  const { stdout } = await run('apt list --upgradable 2>/dev/null | tail -n +2 || echo ""');
  const packages = stdout.split('\n').filter(Boolean).map(l => {
    const match = l.match(/^([^/]+)\/\S+ (\S+)/);
    return match ? { name: match[1], version: match[2] } : { name: l, version: '' };
  });
  res.json({ count: packages.length, packages });
});

app.post('/api/packages/install', requireAuth, async (req, res) => {
  const { name } = req.body;
  if (!name || !/^[a-z0-9._+-]+$/.test(name)) return res.status(400).json({ error: 'Invalid package name' });
  const { err, stdout } = await run(`DEBIAN_FRONTEND=noninteractive apt-get install -y ${name} 2>&1`, 60000);
  res.json({ success: !err, output: stdout });
});

app.post('/api/packages/remove', requireAuth, async (req, res) => {
  const { name } = req.body;
  if (!name || !/^[a-z0-9._+-]+$/.test(name)) return res.status(400).json({ error: 'Invalid package name' });
  const { err, stdout } = await run(`apt-get remove -y ${name} 2>&1`, 60000);
  res.json({ success: !err, output: stdout });
});

app.post('/api/system/ram-optimize', requireAuth, async (req, res) => {
  const r1 = await run('sync && echo 1 > /proc/sys/vm/drop_caches 2>&1 || echo "attempted"');
  const r2 = await run('pm2 gc 2>&1 || echo "pm2 gc done"');
  res.json({ success: true, output: [r1.stdout, r2.stdout].join('\n') });
});

app.get('/api/system/processes', requireAuth, async (req, res) => {
  const { stdout } = await run("ps aux --sort=-%mem | head -20 | awk 'NR>1{print $1,$2,$3,$4,$11}'");
  const procs = stdout.split('\n').filter(Boolean).map(l => {
    const p = l.split(' ');
    return { user: p[0], pid: p[1], cpu: p[2], mem: p[3], cmd: p.slice(4).join(' ') };
  });
  res.json({ processes: procs });
});

io.use((socket, next) => {
  sessionMiddleware(socket.request, socket.request.res || {}, next);
});

io.on('connection', (socket) => {
  if (!socket.request.session?.loggedIn) { socket.disconnect(); return; }

  const statsInterval = setInterval(async () => {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    let cpu = 0;
    try {
      const { stdout } = await run("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1");
      cpu = parseFloat(stdout) || 0;
    } catch {}
    socket.emit('stats', {
      ram_percent: ((usedMem / totalMem) * 100).toFixed(1),
      cpu_usage_percent: cpu.toFixed(2),
      ram_used_gb: (usedMem / 1e9).toFixed(2),
      ram_free_gb: (freeMem / 1e9).toFixed(2),
      uptime: Math.floor(os.uptime()),
      load_avg: os.loadavg().map(v => v.toFixed(2))
    });
  }, 2000);

  let ptyProcess = null;
  socket.on('terminal:start', () => {
    if (ptyProcess) { ptyProcess.kill(); ptyProcess = null; }
    try {
      ptyProcess = pty.spawn('bash', [], {
        name: 'xterm-256color', cols: 120, rows: 30,
        cwd: process.env.HOME || '/root',
        env: { ...process.env, TERM: 'xterm-256color' }
      });
      ptyProcess.onData(d => socket.emit('terminal:data', d));
      ptyProcess.onExit(() => { socket.emit('terminal:exit'); ptyProcess = null; });
    } catch (err) { socket.emit('terminal:data', `\r\nError: ${err.message}\r\n`); }
  });
  socket.on('terminal:input', d => { if (ptyProcess) ptyProcess.write(d); });
  socket.on('terminal:resize', ({ cols, rows }) => { if (ptyProcess) ptyProcess.resize(cols, rows); });
  socket.on('terminal:stop', () => { if (ptyProcess) { ptyProcess.kill(); ptyProcess = null; } });

  socket.on('disconnect', () => {
    clearInterval(statsInterval);
    if (ptyProcess) { ptyProcess.kill(); ptyProcess = null; }
  });
});

server.listen(PORT, () => {
  console.log('\x1b[36m');
  console.log('  ██╗   ██╗██████╗ ███████╗    ██╗   ██╗██╗');
  console.log('  ██║   ██║██╔══██╗██╔════╝    ██║   ██║██║');
  console.log('  ██║   ██║██████╔╝███████╗    ██║   ██║██║');
  console.log('  ╚██╗ ██╔╝██╔═══╝ ╚════██║    ██║   ██║██║');
  console.log('   ╚████╔╝ ██║     ███████║    ╚██████╔╝██║');
  console.log('    ╚═══╝  ╚═╝     ╚══════╝     ╚═════╝ ╚═╝\x1b[0m');
  console.log('');
  console.log('\x1b[32m  ✓ LiteGuard VPS UI started!\x1b[0m');
  console.log(`\x1b[33m  ➜ http://localhost:\x1b[36m${PORT}\x1b[0m`);
  console.log(`\x1b[33m  ➜ Login: \x1b[36m${LOGIN_USER} \x1b[33m/ \x1b[36m${LOGIN_PASS}\x1b[0m`);
  console.log('');
});
