# MyClover.Tech.SentryLog

**Log Aggregation & Security Alert Platform**

SentryLog collects syslog data from network devices, servers, firewalls, switches, routers, and security products — then provides a real-time dashboard for searching, filtering, and alerting on log patterns.

Part of the [MyClover.Tech](https://myclover.tech) suite. Can run standalone or as a NetMon add-on.

🌐 **Website:** [myclover.tech](https://myclover.tech)

---

## Pricing

| | Community (Free) | Pro | Enterprise |
|---|---|---|---|
| **Monthly** | $0 | **$15/mo** | **$39/mo** |
| **Annual** | $0 | **$150/yr** (save 17%) | **$390/yr** (save 17%) |
| **Sources** | 3 | 50 | Unlimited |
| **Alert Rules** | 5 | 100 | Unlimited |
| **Retention** | 7 days | 90 days | 365 days |

> 💡 **Save more with bundles!** Get SentryLog + [NetMon](https://github.com/jonfulk805-og/MyClover.Tech.NetMon) together:
> - **Suite Pro Bundle:** $25/mo or $250/yr
> - **Suite Enterprise Bundle:** $59/mo or $590/yr
>
> **MSP / Managed Service Provider pricing** also available — per-customer rates for IT service providers. [Contact us](mailto:inforequest@myclover.tech) for details.

---

## Features (v1.0 — Phase 1)

- **Syslog Receiver** — UDP + TCP listeners, RFC 3164 & RFC 5424 parsing, auto-source discovery
- **Dashboard** — Dark-themed web UI with 6 tabs: Overview, Live Logs, Sources, Alert Rules, Alerts, Settings
- **Alert Engine** — Pattern-based rules (contains, regex, exact, starts_with) with severity/source filters and cooldowns
- **SQLite Storage** — WAL mode for fast concurrent reads, indexed queries, configurable retention
- **License Tiers** — Community (free), Pro, Enterprise with feature gating
- **NetMon Integration** — Optional add-on mode to correlate with NetMon device data

---

## Quick Start

### Requirements

- Python 3.10+
- Flask, PyYAML

### Install

```bash
pip install -r requirements.txt
```

### Run

```bash
python sentrylog.py
```

Dashboard opens at **http://localhost:8514**

### Configure

Edit `sentrylog_config.yaml` to set syslog ports, retention, and integration options.

> **Note:** Port 514 (standard syslog) requires elevated privileges. Use ports above 1024 or run as Administrator/root.

---

## Architecture

```
sentrylog.py              -- Main application (syslog receiver + dashboard + API)
sentrylog_config.yaml     -- Configuration file
templates/sentrylog.html  -- Dashboard UI
sentrylog.db              -- SQLite database (auto-created on first run)
```

---

## Feature Comparison by Tier

| Feature | Community (Free) | Pro ($15/mo) | Enterprise ($39/mo) |
|---------|-----------------|--------------|---------------------|
| Sources | 3 | 50 | Unlimited |
| Alert Rules | 5 | 100 | Unlimited |
| Retention | 7 days | 90 days | 365 days |
| Syslog (UDP + TCP) | ✅ | ✅ | ✅ |
| Dashboard | ✅ | ✅ | ✅ |
| Windows EventLog | — | — | Phase 2 |
| Security API Connectors | — | — | Phase 3 |

---

## Roadmap

- **Phase 1** (current): Syslog receiver + Dashboard + Alert rules
- **Phase 2**: Windows Event Log collector (WMI/WinRM agentless)
- **Phase 3**: Security API connectors (CrowdStrike, SentinelOne, Defender, etc.)
- **Phase 4**: Cross-source correlation engine + compliance reporting

---

## License Activation

After purchase, you'll receive a license key by email. Paste it into **Settings > License > Activate** in the dashboard to unlock your tier.

---

## Part of the MyClover.Tech Suite

| Product | Description |
|---------|-------------|
| **[NetMon](https://github.com/jonfulk805-og/MyClover.Tech.NetMon)** | Network monitoring, alerting & security scanning |
| **[SentryLog](https://github.com/jonfulk805-og/myclover.tech.sentrylog)** | Log aggregation & security alert platform |

---

**Built by [MyClover.Tech](https://myclover.tech)**
