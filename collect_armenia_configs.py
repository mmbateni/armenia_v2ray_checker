#!/usr/bin/env python3
"""
Armenia V2Ray Config Collector & Verifier
==========================================
Scrapes 40+ public sources for free V2Ray configs (VMess, VLESS,
Shadowsocks, Trojan, Hysteria2, TUIC, Reality), extracts the server IP
from each config, performs a TCP port-reachability check, and confirms
the IP belongs to Armenia (country code AM) via ip-api.com.

Outputs:
  working_armenia_configs.txt   — one config URI per line, ready to import
  working_armenia_configs.json  — structured JSON with metadata
  by_protocol/vmess.txt         — per-protocol split files
  by_protocol/vless.txt
  by_protocol/ss.txt
  by_protocol/trojan.txt
  by_protocol/hysteria2.txt
  by_protocol/other.txt
"""

import base64
import concurrent.futures
import json
import re
import socket
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Configuration ─────────────────────────────────────────────────────────────

TCP_TIMEOUT   = float(__import__('os').environ.get("SCAN_TCP_TO",   "1.5"))
TCP_WORKERS   = int(  __import__('os').environ.get("SCAN_WORKERS",  "300"))
HTTP_TIMEOUT  = 20
TARGET_CC     = "AM"   # Armenia ISO-3166 country code

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Mobile Safari/537.36"
}

# ── Source URLs ───────────────────────────────────────────────────────────────
# All publicly known repositories and sites that publish free V2Ray configs.
# Each entry: (label, url, format)

RAW_SOURCES = [
    # ── barry-far (updates every 15 min) ──
    ("barry-far/vmess",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",   "text"),
    ("barry-far/vless",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",   "text"),
    ("barry-far/ss",      "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",      "text"),
    ("barry-far/trojan",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",  "text"),
    ("barry-far/all-b64", "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Config_base64_Sub.txt",        "text"),

    # ── ebrasha (updates every 15 min) ──
    ("ebrasha/all",  "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/all_extracted_configs.txt", "text"),

    # ── MatinGhanbari (updates every 15 min, 39 subs) ──
    ("matin/super", "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt", "text"),
    ("matin/vmess", "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",  "text"),
    ("matin/vless", "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",  "text"),
    ("matin/ss",    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",     "text"),
    ("matin/trojan","https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt", "text"),
    ("matin/hy2",   "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt","text"),

    # ── Epodonios bulk (already split by country — Armenia folder) ──
    ("epodonios/AM", "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Armenia/config.txt", "text"),
    ("epodonios/sub1","https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt", "text"),

    # ── ShatakVPN/ConfigForge-V2Ray ──
    ("shatak/all",    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",         "text"),

    # ── SoliSpirit (country-split) ──
    ("solispirit/vmess",  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vmess.txt",   "text"),
    ("solispirit/vless",  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vless.txt",   "text"),

    # ── NiREvil/vless (mega aggregator) ──
    ("nirevil/sub", "https://raw.githubusercontent.com/NiREvil/vless/main/sub/G", "text"),

    # ── 10ium aggregator ──
    ("10ium/mixed", "https://raw.githubusercontent.com/10ium/V2Hub3/main/merged_base64", "text"),

    # ── V2Nodes & openproxylist ──
    ("v2nodes/AM", "https://www.v2nodes.com/country/am/", "html"),
    ("openproxylist/AM", "https://openproxylist.com/v2ray/country/am/", "html"),

    # ── mahdibland/V2Hub ──
    ("mahdibland/mix", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/update/mixed/mixed.txt", "text"),

    # ── Mosifree ──
    ("mosifree/all",     "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/All", "text"),
    
    # =========================================================================
    # ── NEW COMPREHENSIVE SOURCES ADDED ──
    # =========================================================================
    
    # ── yebekhe/TelegramV2rayCollector (Huge Telegram aggregator) ──
    ("yebekhe/mix_b64", "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mix_base64", "text"),
    ("yebekhe/vmess",   "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vmess", "text"),
    ("yebekhe/vless",   "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless", "text"),
    ("yebekhe/trojan",  "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/trojan", "text"),
    ("yebekhe/reality", "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/reality", "text"),
    
    # ── soroushmirzaei/telegram-configs-collector ──
    ("soroush/vmess",  "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess", "text"),
    ("soroush/vless",  "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless", "text"),
    ("soroush/trojan", "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan", "text"),
    ("soroush/ss",     "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/shadowsocks", "text"),

    # ── F0rc3Run/F0rc3Run ──
    ("f0rc3run/vmess",  "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vmess.txt", "text"),
    ("f0rc3run/vless",  "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt", "text"),
    ("f0rc3run/trojan", "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/trojan.txt", "text"),

    # ── ALIILAPRO/v2rayNG-Config ──
    ("aliilapro/all", "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt", "text"),

    # ── aiboboxx/v2rayfree ──
    ("aiboboxx/v2", "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2", "text"),

    # ── mfuu/v2ray ──
    ("mfuu/v2ray", "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray", "text"),

    # ── Leon406/Sub ──
    ("leon406/sub", "https://raw.githubusercontent.com/Leon406/Sub/main/sub/share/all", "text"),

    # ── w1770946466/Auto_proxy ──
    ("autoproxy/all", "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num", "text"),

    # ── freefq/free ──
    ("freefq/v2ray", "https://raw.githubusercontent.com/freefq/free/master/v2", "text"),

    # ── pawdroid/Free-servers ──
    ("pawdroid/sub", "https://raw.githubusercontent.com/pawdroid/Free-servers/main/sub", "text"),
    
    # ── Kwinshadow/TelegramV2rayCollector ──
    ("kwinshadow/mix", "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/configs/mixed", "text"),
    
    # ── Awesome-Free-VMESS ──
    ("awesome/vmess", "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt", "text"),

    # ── vpn-vless-configs-russia (Often has Eastern Europe/Caucasus endpoints) ──
    ("kort0881/vless", "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/vless.txt", "text"),
]

# Regex to extract config URIs from arbitrary text
URI_RE = re.compile(
    r"(vmess|vless|ss|trojan|hysteria2|tuic|hy2|wireguard|wg)://[^\s\"'<>]+",
    re.IGNORECASE,
)

# ── Parsers ───────────────────────────────────────────────────────────────────

def decode_if_base64(text: str) -> str:
    """Try to base64-decode a blob; return decoded string or original."""
    stripped = text.strip().replace("\n", "").replace("\r", "")
    try:
        if not URI_RE.search(text[:200]):
            padded = stripped + "=" * (-len(stripped) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if URI_RE.search(decoded[:200]):
                return decoded
    except Exception:
        pass
    return text


def extract_uris_from_text(text: str) -> list[str]:
    """Extract all V2Ray URIs from a blob of text (handles base64 too)."""
    text = decode_if_base64(text)
    return [m.group(0).strip() for m in URI_RE.finditer(text)]


def extract_uris_from_html(html: str) -> list[str]:
    """Extract URIs embedded in HTML pages (v2nodes, openproxylist, etc.)."""
    return extract_uris_from_text(html)


def parse_host_port(uri: str) -> tuple[str, int] | None:
    """Extract (host, port) from any V2Ray URI scheme. Returns None if unparseable."""
    uri = uri.strip()
    scheme = uri.split("://")[0].lower()

    try:
        if scheme == "vmess":
            b64 = uri[8:]
            padded = b64 + "=" * (-len(b64) % 4)
            obj = json.loads(base64.b64decode(padded).decode("utf-8", errors="ignore"))
            host = str(obj.get("add", "") or obj.get("host", ""))
            port = int(obj.get("port", 0))
            return (host, port) if host and port else None

        elif scheme in ("vless", "trojan", "tuic"):
            body = uri.split("://", 1)[1]
            if "@" in body:
                after_at = body.split("@", 1)[1]
            else:
                after_at = body
            after_at = after_at.split("#")[0].split("?")[0]
            if after_at.startswith("["):
                host = after_at.split("]")[0][1:]
                port = int(after_at.split("]:")[1]) if "]:" in after_at else 443
            elif ":" in after_at:
                parts = after_at.rsplit(":", 1)
                host, port = parts[0], int(parts[1])
            else:
                return None
            return (host, port) if host and port else None

        elif scheme == "ss":
            body = uri[5:]
            body = body.split("#")[0].split("?")[0]
            if "@" in body:
                after_at = body.rsplit("@", 1)[1]
                hostport = after_at
            else:
                try:
                    padded = body + "=" * (-len(body) % 4)
                    decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                    if "@" in decoded:
                        hostport = decoded.rsplit("@", 1)[1]
                    else:
                        return None
                except Exception:
                    return None
            if ":" in hostport:
                parts = hostport.rsplit(":", 1)
                host, port = parts[0], int(parts[1])
                return (host, port) if host and port else None

        elif scheme in ("hysteria2", "hy2"):
            body = uri.split("://", 1)[1]
            if "@" in body:
                after_at = body.split("@", 1)[1]
            else:
                after_at = body
            after_at = after_at.split("#")[0].split("?")[0]
            if ":" in after_at:
                host, port_s = after_at.rsplit(":", 1)
                return (host, int(port_s))

    except Exception:
        pass
    return None

# ── GeoIP check (Enhanced Batching) ───────────────────────────────────────────

def bulk_geoip_filter(hosts: set[str]) -> set[str]:
    """Resolves hosts to IPs, uses batch API to prevent rate limits, returns valid AM hosts."""
    print(f"  Resolving and Geo-locating {len(hosts)} unique hosts in batches...", flush=True)
    
    valid_am_hosts = set()
    host_to_ip = {}
    
    # 1. Resolve hostnames to IPs locally first
    for host in hosts:
        try:
            ip = socket.gethostbyname(host)
            host_to_ip[host] = ip
        except Exception:
            continue
            
    unique_ips = list(set(host_to_ip.values()))
    ip_to_cc = {}
    
    # 2. Query ip-api in batches of 100 (API limit requirement)
    for i in range(0, len(unique_ips), 100):
        batch = [{"query": ip, "fields": "countryCode"} for ip in unique_ips[i:i+100]]
        try:
            r = requests.post("http://ip-api.com/batch", json=batch, timeout=10)
            if r.status_code == 200:
                for req, res in zip(batch, r.json()):
                    if res and res.get("countryCode") == TARGET_CC:
                        ip_to_cc[req["query"]] = TARGET_CC
        except Exception as e:
            print(f"  ! Batch GeoIP failed: {e}")
        time.sleep(1.5) # Respect the rate limit (15 requests per minute for batch)

    # 3. Map back to original hosts
    for host, ip in host_to_ip.items():
        if ip_to_cc.get(ip) == TARGET_CC:
            valid_am_hosts.add(host)
            
    return valid_am_hosts

# ── TCP reachability check ─────────────────────────────────────────────────────

def tcp_ok(host: str, port: int) -> float | None:
    """Try to open a TCP connection. Returns latency in ms, or None on failure."""
    try:
        ip = socket.gethostbyname(host)
        start = time.monotonic()
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            pass
        return round((time.monotonic() - start) * 1000, 1)
    except Exception:
        return None

# ── Protocol classifier ────────────────────────────────────────────────────────

def classify(uri: str) -> str:
    s = uri.split("://")[0].lower()
    if s == "vmess":       return "vmess"
    if s == "vless":       return "vless"
    if s == "ss":          return "ss"
    if s == "trojan":      return "trojan"
    if s in ("hysteria2", "hy2"): return "hysteria2"
    if s == "tuic":        return "tuic"
    return "other"

# ── Scraper ───────────────────────────────────────────────────────────────────

def fetch_source(label: str, url: str, fmt: str) -> list[str]:
    """Fetch one source and return a list of raw V2Ray URI strings."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        if fmt == "html":
            return extract_uris_from_html(r.text)
        else:
            return extract_uris_from_text(r.text)
    except Exception as e:
        print(f"  ! [{label}] failed: {e}", flush=True)
        return []


def collect_all() -> list[str]:
    """Fetch all sources in parallel and return de-duplicated URI list."""
    all_uris: set[str] = set()

    # Increased max_workers from 12 to 24 to speed up the fetching of the new sources.
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        futs = {ex.submit(fetch_source, lbl, url, fmt): lbl
                for lbl, url, fmt in RAW_SOURCES}
        for fut in concurrent.futures.as_completed(futs):
            lbl = futs[fut]
            uris = fut.result()
            before = len(all_uris)
            all_uris.update(uris)
            print(f"  + [{lbl}] {len(uris)} raw → {len(all_uris)-before} new", flush=True)

    print(f"\nTotal unique URIs collected: {len(all_uris)}", flush=True)
    return list(all_uris)

# ── Verifier ──────────────────────────────────────────────────────────────────
def verify_all(uris: list[str]) -> list[dict]:
    # Parse all URIs first to get unique hosts
    parsed_configs = []
    unique_hosts = set()
    
    for uri in uris:
        hp = parse_host_port(uri)
        if hp:
            host, port = hp
            if host and (1 <= port <= 65535):
                parsed_configs.append({"uri": uri, "host": host, "port": port, "protocol": classify(uri)})
                unique_hosts.add(host)

    # Filter hosts by country BEFORE doing TCP checks
    am_hosts = bulk_geoip_filter(unique_hosts)
    print(f"  Filtered down to {len(am_hosts)} unique hosts actually in Armenia.")

    # Only keep configs that belong to Armenia
    am_configs = [c for c in parsed_configs if c["host"] in am_hosts]
    
    results = []
    done = 0

    # Now we only TCP test the Armenian ones
    with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        futs = {ex.submit(tcp_ok, c["host"], c["port"]): c for c in am_configs}
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            c = futs[fut]
            latency = fut.result()
            
            if latency is not None:
                c["latency_ms"] = latency
                c["country"] = TARGET_CC
                results.append(c)
                print(f"  ✓ [{c['protocol'].upper()}] {c['host']}:{c['port']}  {latency}ms", flush=True)

    return sorted(results, key=lambda x: x["latency_ms"])

# ── Writers ───────────────────────────────────────────────────────────────────

def write_outputs(results: list[dict]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open("working_armenia_configs.txt", "w") as f:
        f.write(f"# Armenia V2Ray Configs — verified {now}\n")
        f.write(f"# {len(results)} configs | TCP-reachable + GeoIP=AM\n")
        f.write("# Import this file as a subscription in v2rayNG / Hiddify / NekoBox\n\n")
        for r in results:
            f.write(r["uri"] + "\n")

    with open("working_armenia_configs.json", "w") as f:
        json.dump({"checked_at": now, "count": len(results), "configs": results},
                  f, indent=2)

    proto_dir = Path("by_protocol")
    proto_dir.mkdir(exist_ok=True)

    protos = ["vmess", "vless", "ss", "trojan", "hysteria2", "tuic", "other"]
    buckets: dict[str, list[str]] = {p: [] for p in protos}
    for r in results:
        buckets[r["protocol"]].append(r["uri"])

    for proto, uris in buckets.items():
        path = proto_dir / f"{proto}.txt"
        with open(path, "w") as f:
            f.write(f"# {proto.upper()} — Armenia — {now}\n")
            f.write(f"# {len(uris)} configs\n\n")
            for u in uris:
                f.write(u + "\n")

    raw_uris = "\n".join(r["uri"] for r in results)
    b64_sub  = base64.b64encode(raw_uris.encode()).decode()
    with open("working_armenia_configs_base64.txt", "w") as f:
        f.write(b64_sub)

    print(f"\nOutputs written:")
    print(f"  working_armenia_configs.txt         ({len(results)} configs)")
    print(f"  working_armenia_configs.json")
    print(f"  working_armenia_configs_base64.txt  (subscription-ready)")
    for proto in protos:
        n = len(buckets[proto])
        if n:
            print(f"  by_protocol/{proto}.txt   ({n})")

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    sep = "=" * 60
    print(sep)
    print("Armenia V2Ray Config Collector — starting")
    print(f"Target country: {TARGET_CC}  |  TCP timeout: {TCP_TIMEOUT}s"
          f"  |  Workers: {TCP_WORKERS}")
    print(sep)

    print("\n[1/3] Collecting from all sources…")
    uris = collect_all()

    print(f"\n[2/3] Verifying {len(uris)} configs (GeoIP + TCP)…")
    results = verify_all(uris)

    print(f"\n[3/3] Writing outputs…")
    write_outputs(results)

    print(f"\n{sep}")
    print(f"Done — {len(results)} working Armenian V2Ray configs found.")
    print(sep)

if __name__ == "__main__":
    main()
