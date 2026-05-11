# Ubuntu LTS Server Setup — MyClover.Tech.SentryLog

Complete guide for deploying MyClover.Tech.SentryLog on a fresh Ubuntu LTS server (22.04 or 24.04).

> **Also deploying NetMon?** See the [Combined NetMon + SentryLog Setup](#combined-netmon--sentrylog-deployment) section at the bottom, or check the [NetMon repo](https://github.com/jonfulk805-og/MyClover.Tech.NetMon) for its standalone guide.

---

## Table of Contents

1. [Server Requirements](#server-requirements)
2. [Base Server Setup](#1-base-server-setup)
3. [Install SentryLog](#2-install-sentrylog)
4. [Run as a systemd Service](#3-run-as-a-systemd-service)
5. [Firewall Configuration](#4-firewall-configuration)
6. [Syslog Port Configuration](#5-syslog-port-configuration)
7. [Reverse Proxy with Nginx + SSL](#6-reverse-proxy-with-nginx--ssl)
8. [Connecting Log Sources](#7-connecting-log-sources)
9. [NetMon Integration](#8-netmon-integration)
10. [Windows Event Log Collection](#9-windows-event-log-collection-enterprise)
11. [Security API Connectors](#10-security-api-connectors-enterprise)
12. [Backups](#11-backups)
13. [Updating](#12-updating)
14. [Troubleshooting](#13-troubleshooting)
15. [Combined NetMon + SentryLog Deployment](#combined-netmon--sentrylog-deployment)

---

## Server Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| **CPU** | 1 core | 2+ cores |
| **RAM** | 512 MB | 2-4 GB |
| **Disk** | 20 GB | 50-100+ GB (logs grow fast) |
| **Python** | 3.10+ | 3.12+ |
| **Network** | Ports 514, 8514 | Ports 514, 443 via Nginx |

> **Disk sizing tip:** 1 million syslog messages ~ 500 MB in SQLite. Plan for your log volume x retention days.

---

## 1. Base Server Setup

Start with a fresh Ubuntu LTS install (minimal or server edition).

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install core dependencies
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    net-tools \
    ufw

# Set your timezone (adjust as needed)
sudo timedatectl set-timezone America/Los_Angeles

# Verify Python version (must be 3.10+)
python3 --version
```

### Create a dedicated service user (recommended)

```bash
sudo useradd -r -m -s /bin/bash sentrylog
```

---

## 2. Install SentryLog

```bash
# Create application directory
sudo mkdir -p /opt/myclover/sentrylog
sudo chown sentrylog:sentrylog /opt/myclover/sentrylog

# Switch to service user
sudo -u sentrylog -i

# Clone the repository
cd /opt/myclover/sentrylog
git clone https://github.com/jonfulk805-og/myclover.tech.sentrylog.git .

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Optional: Install extras for advanced features
pip install requests    # Security API connectors (Enterprise)
pip install pywinrm     # Remote Windows Event Log (Enterprise, any OS)
# pip install pywin32   # Local Windows Event Log (Windows only)
```

### Configure SentryLog

```bash
nano sentrylog_config.yaml
```

Key settings to review:

```yaml
# Syslog listener ports
syslog:
  udp_enabled: true
  udp_port: 514       # Standard syslog - needs root or CAP_NET_BIND_SERVICE
  tcp_enabled: true
  tcp_port: 514
  buffer_size: 8192

# Storage
storage:
  retention_days: 30   # Community: max 7, Pro: 90, Enterprise: 365
  cleanup_interval_hours: 6
  max_db_size_mb: 500

# Dashboard
dashboard:
  host: 0.0.0.0
  port: 8514

# Email alerts
alerting:
  email:
    enabled: false
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    username: ""
    password: ""
    from_addr: "sentrylog@yourdomain.com"
    recipients: []
```

### Test run

```bash
# Still as sentrylog user with venv active
python sentrylog.py
```

Open your browser to `http://YOUR_SERVER_IP:8514` — you should see the dashboard. Press `Ctrl+C` to stop.

---

## 3. Run as a systemd Service

```bash
# Exit back to your admin user
exit

# Create the service file
sudo tee /etc/systemd/system/sentrylog.service << 'EOF'
[Unit]
Description=MyClover.Tech.SentryLog - Log Aggregation & Security Alerts
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=sentrylog
Group=sentrylog
WorkingDirectory=/opt/myclover/sentrylog
ExecStart=/opt/myclover/sentrylog/venv/bin/python sentrylog.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

# Allow binding to privileged port 514
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/myclover/sentrylog

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable sentrylog
sudo systemctl start sentrylog

# Check status
sudo systemctl status sentrylog

# View live logs
sudo journalctl -u sentrylog -f
```

---

## 4. Firewall Configuration

```bash
# Allow SSH
sudo ufw allow 22/tcp

# Syslog (devices send logs to these ports)
sudo ufw allow 514/udp
sudo ufw allow 514/tcp

# SentryLog web dashboard
sudo ufw allow 8514/tcp

# If using Nginx reverse proxy
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
sudo ufw status
```

---

## 5. Syslog Port Configuration

Standard syslog uses port 514, which is a privileged port (< 1024).

### Option A: Use AmbientCapabilities (recommended)

The systemd service file above includes `AmbientCapabilities=CAP_NET_BIND_SERVICE`, which lets the Python process bind to port 514 without running as root.

### Option B: Use a high port

If you don't need port 514, change the config to use ports above 1024:

```yaml
syslog:
  udp_port: 1514
  tcp_port: 1514
```

Then adjust firewall rules accordingly.

### Option C: Port redirect with iptables

Forward port 514 to a high port:

```bash
sudo iptables -t nat -A PREROUTING -p udp --dport 514 -j REDIRECT --to-port 1514
sudo iptables -t nat -A PREROUTING -p tcp --dport 514 -j REDIRECT --to-port 1514

# Make persistent
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

---

## 6. Reverse Proxy with Nginx + SSL

For production deployments with HTTPS:

```bash
# Install Nginx and Certbot
sudo apt install -y nginx certbot python3-certbot-nginx

# Create Nginx site config
sudo tee /etc/nginx/sites-available/sentrylog << 'EOF'
server {
    listen 80;
    server_name sentrylog.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8514;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (for live log tailing)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

# Enable the site
sudo ln -s /etc/nginx/sites-available/sentrylog /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Get free SSL certificate
sudo certbot --nginx -d sentrylog.yourdomain.com
```

---

## 7. Connecting Log Sources

### Network devices (routers, switches, firewalls)

Set the syslog server on each device to:

```
Server: YOUR_SERVER_IP
Port: 514
Protocol: UDP (or TCP for reliable delivery)
```

SentryLog auto-discovers new sources as logs arrive.

### Linux servers

```bash
# Install rsyslog (usually pre-installed)
sudo apt install -y rsyslog

# Add remote syslog target
echo '*.* @YOUR_SENTRYLOG_IP:514'  | sudo tee -a /etc/rsyslog.d/90-sentrylog.conf  # UDP
# echo '*.* @@YOUR_SENTRYLOG_IP:514' | sudo tee -a /etc/rsyslog.d/90-sentrylog.conf  # TCP (double @)

sudo systemctl restart rsyslog
```

### Windows servers

Use the NXLog Community Edition or built-in Windows Event Forwarding:

```
# NXLog config snippet (nxlog.conf)
<Output sentrylog>
    Module  om_udp
    Host    YOUR_SENTRYLOG_IP
    Port    514
</Output>
```

Or use SentryLog's built-in Windows Event Log collector (Enterprise tier — see below).

### pfSense / OPNsense

Navigate to **Status > System Logs > Settings**:
- Enable Remote Logging
- Remote log server: `YOUR_SENTRYLOG_IP:514`
- Select log categories to forward

### Ubiquiti / UniFi

In the UniFi Controller under **Settings > System > Remote Syslog**:
- Enable Remote Syslog
- Syslog Host: `YOUR_SENTRYLOG_IP`
- Port: `514`

---

## 8. NetMon Integration

Connect SentryLog with NetMon for cross-product device correlation:

```yaml
# In sentrylog_config.yaml
netmon_integration:
  enabled: true
  netmon_url: "http://localhost:8080"  # or http://netmon.yourdomain.com
```

This allows SentryLog to:
- Cross-reference log sources with NetMon-monitored devices
- Show device status alongside log data
- Link between the two dashboards

---

## 9. Windows Event Log Collection (Enterprise)

SentryLog Enterprise can collect Windows Event Logs remotely without agents:

```bash
# Install WinRM library
pip install pywinrm
```

Configure targets in the SentryLog dashboard under **Sources > Windows Event Log**, or via API:

```bash
curl -X POST http://localhost:8514/api/windows-targets \
  -H "Content-Type: application/json" \
  -d '{
    "host": "192.168.1.100",
    "username": "admin",
    "password": "password",
    "channels": "Security,System,Application",
    "poll_interval": 60
  }'
```

### Windows server requirements

The target Windows servers need:
- WinRM enabled: `winrm quickconfig`
- Firewall: Allow port 5985 (HTTP) or 5986 (HTTPS)
- User with Event Log read permissions

---

## 10. Security API Connectors (Enterprise)

Connect to security vendors for centralized alerting:

```bash
# Install requests library
pip install requests
```

Supported connectors:
- **CrowdStrike** — Falcon detection events
- **SentinelOne** — Threat/alert events
- **Microsoft Defender** — Security alerts
- **Sophos Central** — Alert events
- **Cortex XDR** — Incidents/alerts
- **Generic REST** — Any JSON API endpoint

Configure in the dashboard under **Sources > Security Connectors**, or via API.

---

## 11. Backups

### Manual backup

```bash
# Stop the service briefly for a clean backup
sudo systemctl stop sentrylog
sudo -u sentrylog cp /opt/myclover/sentrylog/sentrylog.db /opt/myclover/sentrylog/backups/sentrylog_$(date +%Y%m%d).db
sudo -u sentrylog cp /opt/myclover/sentrylog/sentrylog_config.yaml /opt/myclover/sentrylog/backups/sentrylog_config_$(date +%Y%m%d).yaml
sudo systemctl start sentrylog
```

### Automated daily backup via cron

```bash
sudo -u sentrylog mkdir -p /opt/myclover/sentrylog/backups
sudo -u sentrylog crontab -e
```

Add:

```
0 3 * * * sqlite3 /opt/myclover/sentrylog/sentrylog.db ".backup '/opt/myclover/sentrylog/backups/sentrylog_$(date +\%Y\%m\%d).db'" && find /opt/myclover/sentrylog/backups/ -name "*.db" -mtime +14 -delete
```

> Uses SQLite's online backup API — safe while SentryLog is running.

---

## 12. Updating

```bash
# Stop the service
sudo systemctl stop sentrylog

# Backup
sudo -u sentrylog bash -c '
    cd /opt/myclover/sentrylog
    cp sentrylog.db sentrylog.db.bak
    cp sentrylog_config.yaml sentrylog_config.yaml.bak
'

# Pull latest
sudo -u sentrylog bash -c '
    cd /opt/myclover/sentrylog
    git pull origin main
    source venv/bin/activate
    pip install -r requirements.txt
'

# Restart
sudo systemctl start sentrylog
sudo systemctl status sentrylog
```

---

## 13. Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u sentrylog -n 50 --no-pager

# Check if ports are in use
sudo ss -tlnup | grep -E '514|8514'

# Test manually
sudo -u sentrylog /opt/myclover/sentrylog/venv/bin/python /opt/myclover/sentrylog/sentrylog.py
```

### Permission denied on port 514

```bash
# Verify the systemd service has AmbientCapabilities
grep -i ambient /etc/systemd/system/sentrylog.service

# Or switch to a high port (1514) in sentrylog_config.yaml
```

### No logs arriving

```bash
# Test UDP syslog reception
echo "<14>Test message from command line" | nc -u -w1 localhost 514

# Test TCP syslog reception
echo "<14>Test message from command line" | nc -w1 localhost 514

# Check if firewall allows syslog
sudo ufw status | grep 514

# Verify listener is running
sudo ss -tlnup | grep 514
```

### Database getting too large

```bash
# Check current size
du -h /opt/myclover/sentrylog/sentrylog.db

# Reduce retention in config
# storage:
#   retention_days: 7

# Force cleanup
curl -X POST http://localhost:8514/api/maintenance/cleanup

# Compact database (reclaim disk space)
sudo systemctl stop sentrylog
sudo -u sentrylog sqlite3 /opt/myclover/sentrylog/sentrylog.db "VACUUM;"
sudo systemctl start sentrylog
```

### Dashboard loads but no data

- Verify syslog listeners are running (check `sudo ss -tlnup | grep 514`)
- Send a test log message (see "No logs arriving" above)
- Check browser console (F12) for JavaScript errors

---

## Combined NetMon + SentryLog Deployment

Deploy both products on the same Ubuntu LTS server. See the full combined setup guide in the [NetMon SETUP_UBUNTU.md](https://github.com/jonfulk805-og/MyClover.Tech.NetMon/blob/main/SETUP_UBUNTU.md#combined-netmon--sentrylog-deployment).

### Quick summary

```
/opt/myclover/
├── netmon/        # Port 8080 — network monitoring
└── sentrylog/     # Port 8514 — log aggregation
```

| Service | URL | Purpose |
|---------|-----|---------|
| NetMon | `http://server:8080` | Device monitoring, alerting, security scanning |
| SentryLog | `http://server:8514` | Syslog receiver, log search, alerts |
| Syslog (UDP) | `server:514` | Network devices send logs here |
| Syslog (TCP) | `server:514` | Reliable log delivery |

Both share a single Nginx reverse proxy with SSL and run under the same `myclover` service user.

---

**Built by [MyClover.Tech](https://myclover.tech)**
