<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00e5ff,100:00ff88&height=200&section=header&text=LiteGuard%20VPS%20UI&fontSize=48&fontColor=ffffff&fontAlignY=38&desc=Full-Stack%20VPS%20Desktop%20Management%20Panel&descAlignY=60&descColor=a0d8ef" width="100%"/>

<br/>

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-43853d?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org)
[![Express](https://img.shields.io/badge/Express-4.x-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com)
[![Socket.io](https://img.shields.io/badge/Socket.io-4.x-010101?style=for-the-badge&logo=socket.io&logoColor=white)](https://socket.io)
[![License](https://img.shields.io/badge/License-MIT-00e5ff?style=for-the-badge)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-00ff88?style=for-the-badge)](https://github.com/NimeshMihiranga)

<br/>

```
  ██╗     ██╗████████╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██║     ██║╚══██╔══╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║     ██║   ██║   █████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║     ██║   ██║   ██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ███████╗██║   ██║   ███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚══════╝╚═╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

### 🛡️ A Windows-like Desktop GUI for managing your VPS — right from the browser

<br/>

</div>

---

## ✨ What is LiteGuard?

**LiteGuard VPS UI** is a premium, open-source browser-based desktop environment for managing Linux VPS servers. No SSH client needed. No complex setup. Just open your browser and manage everything from a beautiful, dark neon-themed interface.

> Built specifically for low-resource VPS servers (1GB–6GB RAM). Lightweight, fast, and powerful.

---

## 🖥️ Preview

<div align="center">

| Desktop View | Mobile View |
|:---:|:---:|
| Windows-like draggable windows | Bottom navigation, touch-friendly |
| PM2 Manager, File Manager, Terminal | CPU & RAM gauges, PM2 controls |
| Neon dark theme | Fully responsive |

</div>

---

## 🚀 Features

### 📊 Resource Monitor
- Live **CPU usage** gauge with 60-point history chart
- Live **RAM usage** circular gauge
- Disk, uptime, load average display
- Top processes table (real-time)
- **🌿 Eco Status** — efficiency score for your server
- ⚡ One-click **RAM Optimizer**

### 📁 File Manager
- Browse your entire filesystem
- **Upload & Download** files from browser
- **Create folders**, rename, delete
- Built-in **code editor** with syntax coloring
- List view with file sizes and dates

### 💻 Web Terminal
- Full **bash session** inside the browser
- Real PTY (pseudo-terminal) — runs actual shell
- Color support, tab completion, all Linux commands
- No SSH client required

### ⚙️ PM2 Process Manager
- View all running **PM2 processes**
- **Start / Stop / Restart / Delete** with one click
- Per-process CPU and RAM usage
- Built-in **log viewer** and log flush

### 🛡️ Firewall Manager (UFW)
- View all UFW rules
- **Allow / Deny** ports with protocol selection
- Enable / Disable UFW
- Delete rules with one click

### ⏰ Cron Job Manager
- Full **crontab editor** in browser
- Quick-add templates (hourly, daily, weekly, on reboot)
- Save cron jobs directly from UI

### 👤 User Manager
- List all system users
- **Add new users** with optional sudo access
- **Delete users** and their home directories
- **Change passwords** from browser

### 🌐 Nginx Manager
- View all sites (available & enabled)
- **Enable / Disable** sites
- Edit **Nginx config files** directly
- Reload Nginx with config test

### 📦 Package Manager
- Install / Remove **apt packages**
- Check for **available updates**
- View upgrade list with version info

### 📱 Mobile View
- Automatically detects mobile devices
- CPU & RAM circular gauges
- PM2 controls (start/stop/restart)
- System info page
- Bottom tab navigation

---

## ⚡ Quick Install

### Prerequisites
```bash
# Node.js 18+ required
node --version

# PM2 (optional, recommended for keeping panel alive)
npm install -g pm2
```

### 1. Clone Repository
```bash
git clone https://github.com/NimeshMihiranga/liteguard-vps-ui.git
cd liteguard-vps-ui
```

### 2. Install Dependencies
```bash
# Install build tools (required for web terminal)
apt-get update && apt-get install -y python3 make g++ build-essential

# Install Node dependencies
npm install
```

### 3. Start Panel
```bash
# Direct start
node server.js

# OR with PM2 (recommended - stays alive after disconnect)
pm2 start server.js --name liteguard
pm2 save
pm2 startup
```

### 4. Open Browser
```
http://YOUR-VPS-IP:3000
```

**Default credentials:**
```
Username: admin
Password: admin123
```

> ⚠️ Change credentials immediately after first login!

---

## 🔐 Change Credentials

```bash
# Using environment variables
PANEL_USER=myuser PANEL_PASS=supersecurepass node server.js

# With PM2
pm2 start server.js --name liteguard \
  --env PANEL_USER=myuser \
  --env PANEL_PASS=mypassword
```

---

## 🔧 Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Panel port |
| `PANEL_USER` | `admin` | Login username |
| `PANEL_PASS` | `admin123` | Login password |

```bash
PORT=8080 PANEL_USER=root PANEL_PASS=mypass node server.js
```

---

## 📁 Project Structure

```
liteguard-vps-ui/
│
├── server.js              ← Express backend + Socket.io + PTY terminal
├── package.json           ← Dependencies
│
└── public/
    ├── login.html         ← Secure login page
    └── ui.html            ← Full desktop + mobile UI
```

---

## 🛠️ Troubleshooting

**Terminal not working?**
```bash
# Rebuild node-pty from source
npm rebuild node-pty

# Or force install
npm install node-pty --build-from-source
```

**Port already in use?**
```bash
PORT=8080 node server.js
# Or kill existing process
fuser -k 3000/tcp
```

**PM2 not found?**
```bash
npm install -g pm2
```

**Permission denied errors?**
```bash
# Run with sudo for full system access
sudo node server.js

# Or give node elevated permissions
sudo setcap 'cap_net_bind_service=+ep' $(which node)
```

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `express` | Web server |
| `express-session` | Login session management |
| `socket.io` | Real-time stats & terminal data |
| `node-pty` | Pseudo-terminal for web terminal |
| `multer` | File upload handling |

---

## 🔒 Security Notes

- Session-based authentication — no JWT complexity
- All API routes protected with `requireAuth` middleware
- Terminal spawns bash as the server's running user
- File operations restricted to authenticated users
- **Recommendation:** Run behind Nginx with SSL/HTTPS

### Nginx Reverse Proxy (Recommended)
```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## 🤝 Contributing

Contributions are always welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

<div align="center">

<br/>

**⭐ If this project helped you, please give it a star! ⭐**

<br/>

---

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00ff88,100:00e5ff&height=100&section=footer" width="100%"/>

### Powered by [Nimesh Mihiranga](https://github.com/NimeshMihiranga)

[![GitHub](https://img.shields.io/badge/GitHub-NimeshMihiranga-00e5ff?style=for-the-badge&logo=github)](https://github.com/NimeshMihiranga)

*Built with ❤️ and lots of ☕*

</div>
