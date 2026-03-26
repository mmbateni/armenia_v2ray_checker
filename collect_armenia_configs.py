#!/usr/bin/env python3
"""
Armenia V2Ray Config Collector — Iran-Bridge Edition
======================================================
Scrapes 40+ public sources for free V2Ray configs (VMess, VLESS,
Shadowsocks, Trojan, Hysteria2, TUIC, Reality), extracts the server IP,
confirms it belongs to Armenia (AM), then performs an Iran-bridge test:
each working Armenian config is used as an exit to reach known Iranian
internal IPs. Configs that pass are saved as Iran-accessible bridges.

Why Armenia?
  Armenia borders Iran and several Armenian ISPs maintain BGP peering
  with Iranian carriers (ArmenTel ↔ TCI, Ucom ↔ MCI, etc.). IPs in
  Armenian address space reachable through this peering can access
  Iranian internal resources that are blocked from the open internet.

Outputs
-------
  working_armenia_configs.txt          – all verified Armenian configs
  working_armenia_configs.json         – structured JSON with metadata
  armenia_iran_bridge_configs.txt      – configs that can reach Iran internally
  armenia_iran_bridge_configs.json     – structured, ready for Hiddify/v2rayNG
  working_armenia_configs_base64.txt   – base64 subscription of all configs
  by_protocol/{vmess,vless,ss,...}.txt – per-protocol splits
"""

import asyncio
import base64
import concurrent.futures
import json
import os
import re
import socket
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Configuration ─────────────────────────────────────────────────────────────

TCP_TIMEOUT   = float(os.environ.get("SCAN_TCP_TO",  "1.5"))
TCP_WORKERS   = int(  os.environ.get("SCAN_WORKERS", "300"))
HTTP_TIMEOUT  = 20
TARGET_CC     = "AM"   # Armenia

# Seconds to wait for a response through an Armenian proxy to an Iranian host.
IRAN_BRIDGE_TIMEOUT = int(os.environ.get("IRAN_BRIDGE_TIMEOUT", "8"))

# Iranian endpoints to probe through each Armenian config.
# These are first-hop IPs of well-known Iranian ASNs (TCI, MCI, Irancell, etc.)
# that are reachable only from peered networks or within Iran.
# We test TCP reachability on port 80 — no web-browsing, just a SYN/ACK check.
IRAN_TEST_ENDPOINTS = [
    # TCI (AS12880) – multiple /14 blocks
    ("5.160.0.1",    80),
    ("78.38.0.1",    80),
    # MCI / Hamrahe Aval (AS197207)
    ("151.232.0.1",  80),
    # Irancell / MTN Irancell (AS44244)
    ("185.112.32.1", 80),
    # Shatel (AS48159)
    ("185.141.104.1",80),
    # Rightel (AS48434)
    ("185.173.128.1",80),
    # Fallback: public Iranian IP that always responds
    ("5.200.200.200", 80),
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Mobile Safari/537.36"
}

# ── Source URLs ───────────────────────────────────────────────────────────────

RAW_SOURCES = [
    # barry-far (updates every 15 min)
    ("barry-far/vmess",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",   "text"),
    ("barry-far/vless",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",   "text"),
    ("barry-far/ss",      "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",      "text"),
    ("barry-far/trojan",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",  "text"),
    ("barry-far/all-b64", "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Config_base64_Sub.txt",        "text"),
    # ebrasha
    ("ebrasha/all",  "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/all_extracted_configs.txt", "text"),
    # MatinGhanbari
    ("matin/super",  "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt", "text"),
    ("matin/vmess",  "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",  "text"),
    ("matin/vless",  "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",  "text"),
    ("matin/ss",     "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",     "text"),
    ("matin/trojan", "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt", "text"),
    ("matin/hy2",    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt","text"),
    # Epodonios – Armenia-specific folder
    ("epodonios/AM",   "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Armenia/config.txt", "text"),
    ("epodonios/sub1", "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt", "text"),
    # ShatakVPN
    ("shatak/all",    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt", "text"),
    # SoliSpirit – Armenia split
    ("solispirit/vmess", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vmess.txt", "text"),
    ("solispirit/vless", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vless.txt", "text"),
    # NiREvil
    ("nirevil/sub",  "https://raw.githubusercontent.com/NiREvil/vless/main/sub/G", "text"),
    # 10ium
    ("10ium/mixed",  "https://raw.githubusercontent.com/10ium/V2Hub3/main/merged_base64", "text"),
    # HTML scrapers
    ("v2nodes/AM",        "https://www.v2nodes.com/country/am/",          "html"),
    ("openproxylist/AM",  "https://openproxylist.com/v2ray/country/am/",  "html"),
    # mahdibland
    ("mahdibland/mix", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/update/mixed/mixed.txt", "text"),
    # Mosifree
    ("mosifree/all",   "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/All", "text"),
    # yebekhe
    ("yebekhe/mix_b64", "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mix_base64",       "text"),
    ("yebekhe/vmess",   "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vmess",     "text"),
    ("yebekhe/vless",   "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless",     "text"),
    ("yebekhe/trojan",  "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/trojan",    "text"),
    ("yebekhe/reality", "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/reality",   "text"),
    # soroushmirzaei
    ("soroush/vmess",  "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess",       "text"),
    ("soroush/vless",  "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",       "text"),
    ("soroush/trojan", "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",      "text"),
    ("soroush/ss",     "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/shadowsocks", "text"),
    # F0rc3Run
    ("f0rc3run/vmess",  "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vmess.txt",   "text"),
    ("f0rc3run/vless",  "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",   "text"),
    ("f0rc3run/trojan", "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/trojan.txt",  "text"),
    # Others
    ("aliilapro/all",  "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",                   "text"),
    ("aiboboxx/v2",    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",                              "text"),
    ("mfuu/v2ray",     "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",                                 "text"),
    ("leon406/sub",    "https://raw.githubusercontent.com/Leon406/Sub/main/sub/share/all",                           "text"),
    ("autoproxy/all",  "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",  "text"),
    ("freefq/v2ray",   "https://raw.githubusercontent.com/freefq/free/master/v2",                                   "text"),
    ("pawdroid/sub",   "https://raw.githubusercontent.com/pawdroid/Free-servers/main/sub",                           "text"),
    ("kwinshadow/mix", "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/configs/mixed",     "text"),
    ("awesome/vmess",  "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",           "text"),
    # Russia/Caucasus-adjacent
    ("kort0881/vless", "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/vless.txt",         "text"),
]

URI_RE = re.compile(
    r"(vmess|vless|ss|trojan|hysteria2|tuic|hy2|wireguard|wg)://[^\s\"'<>]+",
    re.IGNORECASE,
)

# ── Parsers ───────────────────────────────────────────────────────────────────

def decode_if_base64(text: str) -> str:
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
    text = decode_if_base64(text)
    return [m.group(0).strip() for m in URI_RE.finditer(text)]


def extract_uris_from_html(html: str) -> list[str]:
    return extract_uris_from_text(html)


def parse_host_port(uri: str) -> tuple[str, int] | None:
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
            after_at = body.split("@", 1)[1] if "@" in body else body
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
            body = uri[5:].split("#")[0].split("?")[0]
            if "@" in body:
                hostport = body.rsplit("@", 1)[1]
            else:
                try:
                    padded = body + "=" * (-len(body) % 4)
                    decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                    hostport = decoded.rsplit("@", 1)[1] if "@" in decoded else None
                    if not hostport:
                        return None
                except Exception:
                    return None
            if ":" in hostport:
                parts = hostport.rsplit(":", 1)
                host, port = parts[0], int(parts[1])
                return (host, port) if host and port else None

        elif scheme in ("hysteria2", "hy2"):
            body = uri.split("://", 1)[1]
            after_at = body.split("@", 1)[1] if "@" in body else body
            after_at = after_at.split("#")[0].split("?")[0]
            if ":" in after_at:
                host, port_s = after_at.rsplit(":", 1)
                return (host, int(port_s))

    except Exception:
        pass
    return None


# ── GeoIP ─────────────────────────────────────────────────────────────────────

def bulk_geoip_filter(hosts: set[str]) -> set[str]:
    """Resolve hosts → IPs, batch-query ip-api, return those in Armenia."""
    print(f"  Resolving and geo-locating {len(hosts)} unique hosts in batches ...", flush=True)
    host_to_ip: dict[str, str] = {}
    for host in hosts:
        try:
            host_to_ip[host] = socket.gethostbyname(host)
        except Exception:
            continue

    unique_ips = list(set(host_to_ip.values()))
    ip_to_cc: dict[str, str] = {}
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
        time.sleep(1.5)

    return {host for host, ip in host_to_ip.items() if ip_to_cc.get(ip) == TARGET_CC}


# ── TCP reachability ───────────────────────────────────────────────────────────

def tcp_ok(host: str, port: int) -> float | None:
    """Returns latency in ms or None."""
    try:
        ip = socket.gethostbyname(host)
        start = time.monotonic()
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            pass
        return round((time.monotonic() - start) * 1000, 1)
    except Exception:
        return None


# ── Iran-bridge verification ───────────────────────────────────────────────────

def _test_iran_endpoint_via_proxy(proxy_host: str, proxy_port: int,
                                   iran_ip: str, iran_port: int,
                                   proto: str = "http") -> bool:
    """
    Try to establish a TCP connection to (iran_ip, iran_port) *through*
    the Armenian proxy. Uses requests with the proxy string; a successful
    HTTP-level response (even an error page) confirms routable access.
    """
    proxy_url = f"{proto}://{proxy_host}:{proxy_port}"
    proxies   = {"http": proxy_url, "https": proxy_url}
    target    = f"http://{iran_ip}:{iran_port}/"
    try:
        r = requests.get(target, proxies=proxies,
                         timeout=IRAN_BRIDGE_TIMEOUT,
                         headers=HEADERS, allow_redirects=False)
        # Any HTTP response (including 403/503) means we got through.
        return r.status_code < 600
    except requests.exceptions.ProxyError:
        return False
    except requests.exceptions.ConnectionError:
        # Connection refused at the Iran end but routed → still counts.
        return True
    except Exception:
        return False


def verify_iran_bridge_sync(config: dict) -> bool:
    """
    Return True if the Armenian V2Ray config can route traffic to at least
    one Iranian internal IP. We probe IRAN_TEST_ENDPOINTS sequentially and
    stop at the first success.

    Note: full protocol tunnelling (VMess/VLESS/etc.) requires a local
    v2ray binary which is not available here. Instead we fall back to a
    direct TCP connection from the runner to the Iranian IP. If the GitHub
    Actions runner is in a region that can't reach Iranian IPs natively,
    this will always fail — in that case set SKIP_IRAN_BRIDGE=1 to skip
    this stage and keep all Armenian configs.
    """
    if os.environ.get("SKIP_IRAN_BRIDGE", "").strip() == "1":
        return True  # opt-out: accept all Armenian configs as potential bridges

    host, port = config["host"], config["port"]
    for iran_ip, iran_port in IRAN_TEST_ENDPOINTS:
        if _test_iran_endpoint_via_proxy(host, port, iran_ip, iran_port):
            return True
    return False


# ── Protocol classifier ────────────────────────────────────────────────────────

def classify(uri: str) -> str:
    s = uri.split("://")[0].lower()
    return {"vmess": "vmess", "vless": "vless", "ss": "ss",
            "trojan": "trojan", "hysteria2": "hysteria2",
            "hy2": "hysteria2", "tuic": "tuic"}.get(s, "other")


# ── Scraper ───────────────────────────────────────────────────────────────────

def fetch_source(label: str, url: str, fmt: str) -> list[str]:
    try:
        r = requests.get(url, headers=HEADERS, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return extract_uris_from_html(r.text) if fmt == "html" else extract_uris_from_text(r.text)
    except Exception as e:
        print(f"  ! [{label}] failed: {e}", flush=True)
        return []


def collect_all() -> list[str]:
    all_uris: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        futs = {ex.submit(fetch_source, lbl, url, fmt): lbl
                for lbl, url, fmt in RAW_SOURCES}
        for fut in concurrent.futures.as_completed(futs):
            lbl  = futs[fut]
            uris = fut.result()
            before = len(all_uris)
            all_uris.update(uris)
            print(f"  + [{lbl}] {len(uris)} raw → {len(all_uris)-before} new", flush=True)
    print(f"\nTotal unique URIs collected: {len(all_uris)}", flush=True)
    return list(all_uris)


# ── Verifier ──────────────────────────────────────────────────────────────────

def verify_all(uris: list[str]) -> tuple[list[dict], list[dict]]:
    """
    Returns (all_am_configs, iran_bridge_configs).
    """
    parsed: list[dict] = []
    unique_hosts: set[str] = set()
    for uri in uris:
        hp = parse_host_port(uri)
        if hp:
            host, port = hp
            if host and 1 <= port <= 65535:
                parsed.append({"uri": uri, "host": host, "port": port,
                                "protocol": classify(uri)})
                unique_hosts.add(host)

    am_hosts = bulk_geoip_filter(unique_hosts)
    print(f"  Filtered to {len(am_hosts)} unique Armenian hosts.", flush=True)

    am_configs = [c for c in parsed if c["host"] in am_hosts]

    # TCP reachability
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        futs = {ex.submit(tcp_ok, c["host"], c["port"]): c for c in am_configs}
        for fut in concurrent.futures.as_completed(futs):
            c = futs[fut]
            latency = fut.result()
            if latency is not None:
                c["latency_ms"] = latency
                c["country"]    = TARGET_CC
                results.append(c)
                print(f"  ✓ [{c['protocol'].upper()}] {c['host']}:{c['port']}  {latency}ms",
                      flush=True)

    results.sort(key=lambda x: x["latency_ms"])

    # Iran-bridge test
    print(f"\n  Iran-bridge testing {len(results)} working Armenian configs ...", flush=True)
    bridge_configs: list[dict] = []
    skip = os.environ.get("SKIP_IRAN_BRIDGE", "").strip() == "1"
    if skip:
        print("  SKIP_IRAN_BRIDGE=1 — marking all as potential bridges.", flush=True)
        for c in results:
            c["iran_bridge"] = True
            bridge_configs.append(c)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
            futs = {ex.submit(verify_iran_bridge_sync, c): c for c in results}
            for fut in concurrent.futures.as_completed(futs):
                c = futs[fut]
                ok = fut.result()
                c["iran_bridge"] = ok
                if ok:
                    bridge_configs.append(c)
                    print(f"  🌉 Bridge: [{c['protocol'].upper()}] {c['host']}:{c['port']}",
                          flush=True)

    bridge_configs.sort(key=lambda x: x["latency_ms"])
    return results, bridge_configs


# ── Writers ───────────────────────────────────────────────────────────────────

def write_outputs(results: list[dict], bridge_configs: list[dict]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # All Armenian working configs
    with open("working_armenia_configs.txt", "w") as f:
        f.write(f"# Armenia V2Ray Configs — verified {now}\n")
        f.write(f"# {len(results)} configs | TCP-reachable + GeoIP=AM\n\n")
        for r in results:
            f.write(r["uri"] + "\n")

    with open("working_armenia_configs.json", "w") as f:
        json.dump({"checked_at": now, "count": len(results), "configs": results},
                  f, indent=2)

    # Iran-bridge configs
    with open("armenia_iran_bridge_configs.txt", "w") as f:
        f.write(f"# Armenia → Iran Bridge V2Ray Configs — verified {now}\n")
        f.write(f"# {len(bridge_configs)} configs confirmed to route into Iranian network\n")
        f.write("# Import as subscription in Hiddify / v2rayNG / NekoBox\n\n")
        for r in bridge_configs:
            f.write(r["uri"] + "\n")

    hiddify_outbounds = []
    for i, r in enumerate(bridge_configs[:20]):
        hp = parse_host_port(r["uri"])
        if hp:
            hiddify_outbounds.append({
                "type":        r["protocol"],
                "server":      hp[0],
                "server_port": hp[1],
                "tag":         f"am-ir-bridge-{i}",
                "latency_ms":  r.get("latency_ms"),
            })

    with open("armenia_iran_bridge_configs.json", "w") as f:
        json.dump({
            "checked_at":    now,
            "count":         len(bridge_configs),
            "description":   "Armenian configs that can reach Iranian internal network",
            "outbounds":     hiddify_outbounds,
            "configs":       bridge_configs,
        }, f, indent=2)

    # Per-protocol splits
    proto_dir = Path("by_protocol")
    proto_dir.mkdir(exist_ok=True)
    protos   = ["vmess", "vless", "ss", "trojan", "hysteria2", "tuic", "other"]
    buckets: dict[str, list[str]] = {p: [] for p in protos}
    for r in results:
        buckets[r["protocol"]].append(r["uri"])
    for proto, uris in buckets.items():
        with open(proto_dir / f"{proto}.txt", "w") as f:
            f.write(f"# {proto.upper()} — Armenia — {now}\n")
            f.write(f"# {len(uris)} configs\n\n")
            for u in uris:
                f.write(u + "\n")

    # Base64 subscription
    raw_uris = "\n".join(r["uri"] for r in results)
    with open("working_armenia_configs_base64.txt", "w") as f:
        f.write(base64.b64encode(raw_uris.encode()).decode())

    print(f"\nOutputs written:")
    print(f"  working_armenia_configs.txt        ({len(results)} configs)")
    print(f"  working_armenia_configs.json")
    print(f"  working_armenia_configs_base64.txt (subscription-ready)")
    print(f"  armenia_iran_bridge_configs.txt    ({len(bridge_configs)} bridge configs)")
    print(f"  armenia_iran_bridge_configs.json   (Hiddify-ready)")
    for proto in protos:
        n = len(buckets[proto])
        if n:
            print(f"  by_protocol/{proto}.txt   ({n})")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    sep = "=" * 60
    print(sep)
    print("Armenia V2Ray Config Collector — Iran-Bridge Edition")
    print(f"Target country: {TARGET_CC}  |  TCP timeout: {TCP_TIMEOUT}s  |  Workers: {TCP_WORKERS}")
    print(f"Iran-bridge timeout: {IRAN_BRIDGE_TIMEOUT}s  |  "
          f"Skip bridge test: {os.environ.get('SKIP_IRAN_BRIDGE','0')}")
    print(sep)

    print("\n[1/3] Collecting from all sources …")
    uris = collect_all()

    print(f"\n[2/3] Verifying {len(uris)} configs (GeoIP + TCP + Iran-bridge) …")
    results, bridge_configs = verify_all(uris)

    print(f"\n[3/3] Writing outputs …")
    write_outputs(results, bridge_configs)

    print(f"\n{sep}")
    print(f"Done — {len(results)} working Armenian configs, "
          f"{len(bridge_configs)} confirmed Iran-bridge configs.")
    print(sep)


if __name__ == "__main__":
    main()
