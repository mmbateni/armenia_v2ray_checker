#!/usr/bin/env python3
"""
Armenia V2Ray Config Collector & Verifier
==========================================
Scrapes 20+ public sources for free V2Ray configs (VMess, VLESS,
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
#   format = "text"   → plain URI list or base64-encoded URI list
#            "json"   → JSON array / object containing configs

RAW_SOURCES = [
    # ── barry-far (updates every 15 min) ──
    ("barry-far/vmess",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",   "text"),
    ("barry-far/vless",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",   "text"),
    ("barry-far/ss",      "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",      "text"),
    ("barry-far/trojan",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",  "text"),
    ("barry-far/all-b64", "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Config_base64_Sub.txt",        "text"),

    # ── ebrasha (updates every 15 min) ──
    ("ebrasha/all",  "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/all_extracted_configs.txt", "text"),
    ("ebrasha/main", "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha.txt", "text"),

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
    ("epodonios/sub2","https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub2.txt", "text"),
    ("epodonios/sub3","https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub3.txt", "text"),

    # ── ShatakVPN/ConfigForge-V2Ray ──
    ("shatak/all",    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",         "text"),
    ("shatak/vless",  "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/vless.txt",       "text"),
    ("shatak/vmess",  "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/vmess.txt",       "text"),
    ("shatak/ss",     "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/shadowsocks.txt", "text"),
    ("shatak/trojan", "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/trojan.txt",      "text"),

    # ── SoliSpirit (country-split) ──
    ("solispirit/vmess",  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vmess.txt",   "text"),
    ("solispirit/vless",  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vless.txt",   "text"),
    ("solispirit/ss",     "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/shadowsocks.txt","text"),
    ("solispirit/trojan", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/trojan.txt",  "text"),

    # ── hamedcode/port-based ──
    ("hamedcode/all", "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/all_configs.txt", "text"),

    # ── NiREvil/vless (mega aggregator) ──
    ("nirevil/sub", "https://raw.githubusercontent.com/NiREvil/vless/main/sub/G", "text"),

    # ── 10ium aggregator ──
    ("10ium/vless", "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/main/output_configs/Vless.txt",       "text"),
    ("10ium/ss",    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/main/output_configs/ShadowSocks.txt", "text"),
    ("10ium/trojan","https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/main/output_configs/Trojan.txt",      "text"),
    ("10ium/mixed", "https://raw.githubusercontent.com/10ium/V2Hub3/main/merged_base64",                               "text"),

    # ── V2Nodes web scrape (Armenia page) ──
    ("v2nodes/AM", "https://www.v2nodes.com/country/am/", "html"),

    # ── openproxylist.com Armenia V2Ray page ──
    ("openproxylist/AM", "https://openproxylist.com/v2ray/country/am/", "html"),

    # ── MrMohebi/xray-proxy-grabber-telegram ──
    ("mohebi/all", "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt", "text"),

    # ── proxifly aggregator ──
    ("proxifly/all", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt", "text"),

    # ── mahdibland/V2Hub ──
    ("mahdibland/mix", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/update/mixed/mixed.txt", "text"),

    # ── Mosifree ──
    ("mosifree/reality", "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Vless_Reality", "text"),
    ("mosifree/all",     "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/All",           "text"),
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
        # Only try if the text doesn't already contain URIs
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
    # Some sites store configs in data attributes or code blocks
    return extract_uris_from_text(html)


def parse_host_port(uri: str) -> tuple[str, int] | None:
    """
    Extract (host, port) from any V2Ray URI scheme.
    Returns None if unparseable.
    """
    uri = uri.strip()
    scheme = uri.split("://")[0].lower()

    try:
        if scheme == "vmess":
            # VMess: vmess://<base64-encoded-json>
            b64 = uri[8:]
            padded = b64 + "=" * (-len(b64) % 4)
            obj = json.loads(base64.b64decode(padded).decode("utf-8", errors="ignore"))
            host = str(obj.get("add", "") or obj.get("host", ""))
            port = int(obj.get("port", 0))
            return (host, port) if host and port else None

        elif scheme in ("vless", "trojan", "tuic"):
            # vless://uuid@host:port?...#remark
            body = uri.split("://", 1)[1]
            if "@" in body:
                after_at = body.split("@", 1)[1]
            else:
                after_at = body
            # strip fragment
            after_at = after_at.split("#")[0]
            # strip query
            hostport = after_at.split("?")[0]
            if hostport.startswith("["):
                # IPv6
                host = hostport.split("]")[0][1:]
                port = int(hostport.split("]:")[1]) if "]:" in hostport else 443
            elif ":" in hostport:
                parts = hostport.rsplit(":", 1)
                host, port = parts[0], int(parts[1])
            else:
                return None
            return (host, port) if host and port else None

        elif scheme == "ss":
            # ss://BASE64@host:port OR ss://method:pass@host:port
            body = uri[5:]
            # strip fragment/query
            body = body.split("#")[0].split("?")[0]
            if "@" in body:
                after_at = body.rsplit("@", 1)[1]
                hostport = after_at
            else:
                # old style: ss://base64(method:pass)@host:port
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
            # hysteria2://pass@host:port?...
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


# ── GeoIP check ───────────────────────────────────────────────────────────────

_GEOIP_CACHE: dict[str, str] = {}   # ip → country_code


def geoip_country(host: str) -> str:
    """Return ISO-3166 country code for a hostname/IP, or '' on failure."""
    if host in _GEOIP_CACHE:
        return _GEOIP_CACHE[host]
    try:
        # Resolve hostname to IP first
        ip = socket.gethostbyname(host)
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode",
            timeout=8,
        )
        cc = r.json().get("countryCode", "")
        _GEOIP_CACHE[host] = cc
        return cc
    except Exception:
        return ""


# ── TCP reachability check ─────────────────────────────────────────────────────

def tcp_ok(host: str, port: int) -> float | None:
    """
    Try to open a TCP connection to host:port.
    Returns round-trip latency in ms, or None on failure.
    """
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

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
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

def verify_one(uri: str) -> dict | None:
    """
    For a single URI:
    1. Parse host+port
    2. TCP check
    3. GeoIP → must be Armenia (AM)
    Returns result dict or None.
    """
    hp = parse_host_port(uri)
    if not hp:
        return None
    host, port = hp
    if not host or not (1 <= port <= 65535):
        return None

    # Step 1: GeoIP first (cheaper if IP is already cached)
    cc = geoip_country(host)
    if cc != TARGET_CC:
        return None

    # Step 2: TCP reachability
    latency = tcp_ok(host, port)
    if latency is None:
        return None

    return {
        "uri":      uri,
        "protocol": classify(uri),
        "host":     host,
        "port":     port,
        "latency_ms": latency,
        "country":  cc,
    }


def verify_all(uris: list[str]) -> list[dict]:
    """Test all URIs concurrently, return list of passing results."""
    results = []
    total = len(uris)
    done  = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        futs = {ex.submit(verify_one, u): u for u in uris}
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            res = fut.result()
            if res:
                results.append(res)
                print(
                    f"  ✓ [{res['protocol'].upper()}] {res['host']}:{res['port']}"
                    f"  {res['latency_ms']}ms",
                    flush=True,
                )
            if done % 500 == 0:
                print(f"  … {done}/{total} tested, {len(results)} Armenian found",
                      flush=True)

    return sorted(results, key=lambda x: x["latency_ms"])


# ── Writers ───────────────────────────────────────────────────────────────────

def write_outputs(results: list[dict]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── working_armenia_configs.txt ──
    with open("working_armenia_configs.txt", "w") as f:
        f.write(f"# Armenia V2Ray Configs — verified {now}\n")
        f.write(f"# {len(results)} configs | TCP-reachable + GeoIP=AM\n")
        f.write("# Import this file as a subscription in v2rayNG / Hiddify / NekoBox\n\n")
        for r in results:
            f.write(r["uri"] + "\n")

    # ── working_armenia_configs.json ──
    with open("working_armenia_configs.json", "w") as f:
        json.dump({"checked_at": now, "count": len(results), "configs": results},
                  f, indent=2)

    # ── by_protocol/ split files ──
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

    # ── base64 subscription (for apps that require it) ──
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
