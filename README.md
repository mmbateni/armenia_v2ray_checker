# 🇦🇲 Armenia V2Ray Config Collector

Automatically collects, filters, and verifies free V2Ray configs with **Armenian IP addresses** every day at 20:30 UTC.

## What it does

1. **Scrapes 40+ public sources** — GitHub repos, aggregator sites, country-split lists
2. **Parses every config** — VMess, VLESS, Shadowsocks, Trojan, Hysteria2, TUIC, Reality
3. **GeoIP check** — confirms the server IP belongs to Armenia 🇦🇲 via ip-api.com
4. **TCP port check** — confirms the server port is actually reachable
5. **Saves results** in plain text, base64 subscription, JSON, and per-protocol splits

## Output files (updated daily)

| File | Description |
|---|---|
| `working_armenia_configs.txt` | All working configs, one URI per line |
| `working_armenia_configs_base64.txt` | Base64 subscription link (paste into v2rayNG etc.) |
| `working_armenia_configs.json` | Full JSON with host, port, protocol, latency |
| `by_protocol/vmess.txt` | VMess only |
| `by_protocol/vless.txt` | VLESS only |
| `by_protocol/ss.txt` | Shadowsocks only |
| `by_protocol/trojan.txt` | Trojan only |
| `by_protocol/hysteria2.txt` | Hysteria2 only |

## How to use on Android

### Option A — Subscription link (recommended, auto-updates)
1. Open **v2rayNG**, **HiddifyNG**, or **NekoBox**
2. Tap **+** → **Import from URL**
3. Paste:
```
https://raw.githubusercontent.com/YOUR_USERNAME/armenia-v2ray/main/working_armenia_configs_base64.txt
```
4. Tap **Update** → **Test all** → connect to fastest

### Option B — Manual import
1. Open `working_armenia_configs.txt` in this repo
2. Copy any config URI (e.g. `vless://...`)
3. In v2rayNG, tap **+** → **Import config from clipboard**

## Sources scraped

- `barry-far/V2ray-Config` — updates every 15 min
- `ebrasha/free-v2ray-public-list` — updates every 15 min
- `MatinGhanbari/v2ray-configs` — 39 subscription files
- `Epodonios/bulk-xray-v2ray-vless-vmess-...-configs` — pre-split by country (Armenia folder)
- `Epodonios/v2ray-configs` — Sub1–Sub3
- `ShatakVPN/ConfigForge-V2Ray` — latency-tested aggregator
- `SoliSpirit/v2ray-configs` — country-split (Armenia folder)
- `hamedcode/port-based-v2ray-configs`
- `NiREvil/vless` — mega aggregator
- `10ium/ScrapeAndCategorize` — protocol-split
- `mahdibland/V2RayAggregator`
- `MrMohebi/xray-proxy-grabber-telegram`
- `Mosifree/-FREE2CONFIG`
- `v2nodes.com/country/am/`
- `openproxylist.com/v2ray/country/am/`

## Run manually

```bash
pip install requests
python collect_armenia_configs.py
```

## Trigger a manual GitHub Actions run

Go to **Actions → Armenia V2Ray Config Collector → Run workflow**

## Schedule

Runs daily at **20:30 UTC** (midnight Tehran / 12:30 Vancouver).
