#!/usr/bin/env python3
"""
Armenia + Azerbaijan V2Ray Config Collector
============================================
Scrapes 50+ public sources for free V2Ray configs (VMess, VLESS,
Shadowsocks, Trojan, Hysteria2, TUIC, Reality), extracts the server IP,
confirms it belongs to Armenia (AM) **or** Azerbaijan / Baku (AZ),
performs a TCP port check, and saves results per-country, combined,
per-protocol, and as base64 subscriptions.

Outputs
-------
working_configs.txt                    – all verified AM+AZ configs (combined)
working_configs_base64.txt             – base64 subscription (combined)
working_configs.json                   – full JSON with host/port/protocol/latency/country
by_country/armenia.txt                 – Armenia configs only
by_country/armenia_base64.txt          – Armenia base64 subscription
by_country/azerbaijan.txt              – Azerbaijan configs only
by_country/azerbaijan_base64.txt       – Azerbaijan base64 subscription
by_protocol/{vmess,vless,ss,...}.txt   – per-protocol (all countries)
by_protocol/armenia/{proto}.txt        – per-protocol Armenia
by_protocol/azerbaijan/{proto}.txt     – per-protocol Azerbaijan
"""

import base64
import concurrent.futures
import json
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Configuration ──────────────────────────────────────────────────────────────
TCP_TIMEOUT   = float(os.environ.get("SCAN_TCP_TO",  "1.5"))
TCP_WORKERS   = int(  os.environ.get("SCAN_WORKERS", "300"))
HTTP_TIMEOUT  = 20
TARGET_CCS    = {"AM", "AZ"}          # Armenia + Azerbaijan
CC_NAMES      = {"AM": "Armenia", "AZ": "Azerbaijan"}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Mobile Safari/537.36"
    )
}

# ── Source URLs ────────────────────────────────────────────────────────────────
RAW_SOURCES = [
    # ── barry-far (updates every 15 min) ──────────────────────────────────────
    ("barry-far/vmess",    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",   "text"),
    ("barry-far/vless",    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",   "text"),
    ("barry-far/ss",       "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",      "text"),
    ("barry-far/trojan",   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",  "text"),
    ("barry-far/all-b64",  "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Config_base64_Sub.txt",        "text"),

    # ── ebrasha ───────────────────────────────────────────────────────────────
    ("ebrasha/all",        "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/all_extracted_configs.txt", "text"),

    # ── MatinGhanbari ─────────────────────────────────────────────────────────
    ("matin/super",   "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",          "text"),
    ("matin/vmess",   "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",      "text"),
    ("matin/vless",   "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",      "text"),
    ("matin/ss",      "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",         "text"),
    ("matin/trojan",  "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",     "text"),
    ("matin/hy2",     "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",  "text"),

    # ── Epodonios – country-split ─────────────────────────────────────────────
    ("epodonios/AM",  "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Armenia/config.txt",     "text"),
    ("epodonios/AZ",  "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-...-configs/main/sub/Azerbaijan/config.txt",  "text"),
    ("epodonios/sub1","https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub1.txt",                                             "text"),
    ("epodonios/sub2","https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub2.txt",                                             "text"),
    ("epodonios/sub3","https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Sub3.txt",                                             "text"),

    # ── ShatakVPN ─────────────────────────────────────────────────────────────
    ("shatak/all",    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt", "text"),

    # ── SoliSpirit – country-split ────────────────────────────────────────────
    ("solispirit/AM/vmess",  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vmess.txt",     "text"),
    ("solispirit/AM/vless",  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia/vless.txt",     "text"),
    ("solispirit/AZ/vmess",  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Azerbaijan/vmess.txt",  "text"),
    ("solispirit/AZ/vless",  "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Azerbaijan/vless.txt",  "text"),

    # ── MhdiTaheri – country-split ────────────────────────────────────────────
    ("mhdi/AM",  "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Armenia/config.txt",    "text"),
    ("mhdi/AZ",  "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/main/sub/Azerbaijan/config.txt", "text"),

    # ── NiREvil ───────────────────────────────────────────────────────────────
    ("nirevil/sub",   "https://raw.githubusercontent.com/NiREvil/vless/main/sub/G", "text"),

    # ── 10ium ────────────────────────────────────────────────────────────────
    ("10ium/mixed",   "https://raw.githubusercontent.com/10ium/V2Hub3/main/merged_base64",                             "text"),
    ("10ium/reality", "https://raw.githubusercontent.com/10ium/V2Hub3/refs/heads/main/Split/Normal/reality",           "text"),
    ("10ium/hy2",     "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Hysteria2.txt", "text"),

    # ── HTML scrapers ─────────────────────────────────────────────────────────
    ("v2nodes/AM",        "https://www.v2nodes.com/country/am/",           "html"),
    ("v2nodes/AZ",        "https://www.v2nodes.com/country/az/",           "html"),
    ("openproxylist/AM",  "https://openproxylist.com/v2ray/country/am/",   "html"),
    ("openproxylist/AZ",  "https://openproxylist.com/v2ray/country/az/",   "html"),

    # ── mahdibland ───────────────────────────────────────────────────────────
    ("mahdibland/mix",    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/update/mixed/mixed.txt", "text"),

    # ── Mosifree ─────────────────────────────────────────────────────────────
    ("mosifree/all",      "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/All", "text"),

    # ── yebekhe ──────────────────────────────────────────────────────────────
    ("yebekhe/mix_b64",   "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mix_base64",         "text"),
    ("yebekhe/vmess",     "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vmess",       "text"),
    ("yebekhe/vless",     "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless",       "text"),
    ("yebekhe/trojan",    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/trojan",      "text"),
    ("yebekhe/reality",   "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/reality",     "text"),

    # ── soroushmirzaei ───────────────────────────────────────────────────────
    ("soroush/vmess",     "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess",       "text"),
    ("soroush/vless",     "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",       "text"),
    ("soroush/trojan",    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",      "text"),
    ("soroush/ss",        "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/shadowsocks", "text"),

    # ── F0rc3Run ─────────────────────────────────────────────────────────────
    ("f0rc3run/vmess",    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vmess.txt",  "text"),
    ("f0rc3run/vless",    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",  "text"),
    ("f0rc3run/trojan",   "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/trojan.txt", "text"),

    # ── MrMohebi ─────────────────────────────────────────────────────────────
    ("mohebi/mix",        "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt", "text"),

    # ── hamedcode ────────────────────────────────────────────────────────────
    ("hamedcode/ports",   "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/all.txt", "text"),

    # ── Others ────────────────────────────────────────────────────────────────
    ("aliilapro/all",     "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",                                          "text"),
    ("aiboboxx/v2",       "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",                                                     "text"),
    ("mfuu/v2ray",        "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",                                                        "text"),
    ("leon406/sub",       "https://raw.githubusercontent.com/Leon406/Sub/main/sub/share/all",                                                 "text"),
    ("freefq/v2ray",      "https://raw.githubusercontent.com/freefq/free/master/v2",                                                          "text"),
    ("pawdroid/sub",      "https://raw.githubusercontent.com/pawdroid/Free-servers/main/sub",                                                  "text"),
    ("kwinshadow/mix",    "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/configs/mixed",                           "text"),
    ("awesome/vmess",     "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",                                  "text"),
    ("autoproxy/all",     "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",                         "text"),
    # Russia/Caucasus-adjacent (may contain AZ/AM nodes)
    ("kort0881/vless",    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/vless.txt", "text"),
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


def extract_uris_from_text(text: str) -> list:
    text = decode_if_base64(text)
    return [m.group(0).strip() for m in URI_RE.finditer(text)]


def extract_uris_from_html(html: str) -> list:
    return extract_uris_from_text(html)


def parse_host_port(uri: str):
    """Return (host, port) tuple or None."""
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

def bulk_geoip_filter(hosts: set) -> dict:
    """
    Resolve hosts → IPs, batch-query ip-api.com in groups of 100,
    return {host: country_code} for hosts belonging to AM or AZ.
    """
    print(f"  Resolving and geo-locating {len(hosts)} unique hosts …", flush=True)

    host_to_ip = {}
    for host in hosts:
        try:
            host_to_ip[host] = socket.gethostbyname(host)
        except Exception:
            continue

    unique_ips = list(set(host_to_ip.values()))
    ip_to_cc = {}

    for i in range(0, len(unique_ips), 100):
        batch = [{"query": ip, "fields": "countryCode,query"} for ip in unique_ips[i:i+100]]
        try:
            r = requests.post("http://ip-api.com/batch", json=batch, timeout=10)
            if r.status_code == 200:
                for res in r.json():
                    cc = res.get("countryCode", "")
                    if cc in TARGET_CCS:
                        ip_to_cc[res["query"]] = cc
        except Exception as e:
            print(f"  ! Batch GeoIP failed: {e}")
        time.sleep(1.5)   # respect ip-api rate limit

    result = {}
    for host, ip in host_to_ip.items():
        cc = ip_to_cc.get(ip)
        if cc:
            result[host] = cc
    return result


# ── TCP reachability ───────────────────────────────────────────────────────────

def tcp_ok(host: str, port: int):
    """Returns latency in ms or None."""
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
    return {
        "vmess": "vmess", "vless": "vless", "ss": "ss",
        "trojan": "trojan", "hysteria2": "hysteria2",
        "hy2": "hysteria2", "tuic": "tuic",
    }.get(s, "other")


# ── Scraper ───────────────────────────────────────────────────────────────────

def fetch_source(label: str, url: str, fmt: str) -> list:
    try:
        r = requests.get(url, headers=HEADERS, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return extract_uris_from_html(r.text) if fmt == "html" else extract_uris_from_text(r.text)
    except Exception as e:
        print(f"  ! [{label}] failed: {e}", flush=True)
        return []


def collect_all() -> list:
    all_uris: set = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        futs = {ex.submit(fetch_source, lbl, url, fmt): lbl
                for lbl, url, fmt in RAW_SOURCES}
        for fut in concurrent.futures.as_completed(futs):
            lbl = futs[fut]
            uris = fut.result()
            before = len(all_uris)
            all_uris.update(uris)
            added = len(all_uris) - before
            if added:
                print(f"  + [{lbl}] {len(uris)} raw → {added} new", flush=True)
    print(f"\nTotal unique URIs collected: {len(all_uris)}", flush=True)
    return list(all_uris)


# ── Verifier ──────────────────────────────────────────────────────────────────

def verify_all(uris: list) -> list:
    """
    Returns list of verified config dicts with country_code, latency, etc.
    """
    parsed = []
    unique_hosts: set = set()

    for uri in uris:
        hp = parse_host_port(uri)
        if hp:
            host, port = hp
            if host and 1 <= port <= 65535:
                parsed.append({
                    "uri": uri,
                    "host": host,
                    "port": port,
                    "protocol": classify(uri),
                })
                unique_hosts.add(host)

    print(f"  Parsed {len(parsed)} configs with {len(unique_hosts)} unique hosts.", flush=True)

    host_cc = bulk_geoip_filter(unique_hosts)

    print(f"  Found {len(host_cc)} hosts in target countries "
          f"({', '.join(TARGET_CCS)}).", flush=True)

    target_configs = [c for c in parsed if c["host"] in host_cc]

    # TCP reachability
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        futs = {ex.submit(tcp_ok, c["host"], c["port"]): c for c in target_configs}
        for fut in concurrent.futures.as_completed(futs):
            c = futs[fut]
            latency = fut.result()
            if latency is not None:
                c["latency_ms"] = latency
                c["country"] = host_cc[c["host"]]
                c["country_name"] = CC_NAMES[c["country"]]
                results.append(c)
                print(
                    f"  ✓ [{c['country']}][{c['protocol'].upper()}] "
                    f"{c['host']}:{c['port']} {latency}ms",
                    flush=True,
                )

    results.sort(key=lambda x: x["latency_ms"])
    return results


# ── Writers ───────────────────────────────────────────────────────────────────

def write_outputs(results: list) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    am_results = [r for r in results if r["country"] == "AM"]
    az_results = [r for r in results if r["country"] == "AZ"]

    # ── Combined ──────────────────────────────────────────────────────────────
    with open("working_configs.txt", "w") as f:
        f.write(f"# Armenia + Azerbaijan V2Ray Configs — verified {now}\n")
        f.write(f"# {len(results)} configs | Armenia: {len(am_results)} | Azerbaijan: {len(az_results)}\n\n")
        for r in results:
            f.write(r["uri"] + "\n")

    with open("working_configs.json", "w") as f:
        json.dump(
            {"checked_at": now, "count": len(results),
             "armenia_count": len(am_results), "azerbaijan_count": len(az_results),
             "configs": results},
            f, indent=2,
        )

    raw_uris = "\n".join(r["uri"] for r in results)
    with open("working_configs_base64.txt", "w") as f:
        f.write(base64.b64encode(raw_uris.encode()).decode())

    # ── Per-country ───────────────────────────────────────────────────────────
    country_dir = Path("by_country")
    country_dir.mkdir(exist_ok=True)

    for cc, country_results, fname in [
        ("AM", am_results, "armenia"),
        ("AZ", az_results, "azerbaijan"),
    ]:
        name = CC_NAMES[cc]
        with open(country_dir / f"{fname}.txt", "w") as f:
            f.write(f"# {name} V2Ray Configs — verified {now}\n")
            f.write(f"# {len(country_results)} configs | TCP-reachable + GeoIP={cc}\n\n")
            for r in country_results:
                f.write(r["uri"] + "\n")

        raw = "\n".join(r["uri"] for r in country_results)
        with open(country_dir / f"{fname}_base64.txt", "w") as f:
            f.write(base64.b64encode(raw.encode()).decode())

        with open(country_dir / f"{fname}.json", "w") as f:
            json.dump(
                {"checked_at": now, "country": cc, "country_name": name,
                 "count": len(country_results), "configs": country_results},
                f, indent=2,
            )

    # ── Per-protocol (combined) ───────────────────────────────────────────────
    PROTOS = ["vmess", "vless", "ss", "trojan", "hysteria2", "tuic", "other"]
    proto_dir = Path("by_protocol")
    proto_dir.mkdir(exist_ok=True)

    buckets: dict = {p: [] for p in PROTOS}
    for r in results:
        buckets[r["protocol"]].append(r["uri"])

    for proto, uris in buckets.items():
        with open(proto_dir / f"{proto}.txt", "w") as f:
            f.write(f"# {proto.upper()} — Armenia + Azerbaijan — {now}\n")
            f.write(f"# {len(uris)} configs\n\n")
            for u in uris:
                f.write(u + "\n")

    # ── Per-protocol per-country ───────────────────────────────────────────────
    for cc, country_results, dirname in [
        ("AM", am_results, "armenia"),
        ("AZ", az_results, "azerbaijan"),
    ]:
        cdir = proto_dir / dirname
        cdir.mkdir(exist_ok=True)
        cbuckets: dict = {p: [] for p in PROTOS}
        for r in country_results:
            cbuckets[r["protocol"]].append(r["uri"])
        for proto, uris in cbuckets.items():
            with open(cdir / f"{proto}.txt", "w") as f:
                f.write(f"# {proto.upper()} — {CC_NAMES[cc]} — {now}\n")
                f.write(f"# {len(uris)} configs\n\n")
                for u in uris:
                    f.write(u + "\n")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\nOutputs written:")
    print(f"  working_configs.txt               ({len(results)} total configs)")
    print(f"  working_configs_base64.txt         (subscription-ready, combined)")
    print(f"  working_configs.json")
    print(f"  by_country/armenia.txt            ({len(am_results)} configs)")
    print(f"  by_country/armenia_base64.txt      (subscription-ready)")
    print(f"  by_country/azerbaijan.txt          ({len(az_results)} configs)")
    print(f"  by_country/azerbaijan_base64.txt   (subscription-ready)")
    for proto in PROTOS:
        n = len(buckets[proto])
        if n:
            print(f"  by_protocol/{proto}.txt  ({n})")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    sep = "=" * 65
    print(sep)
    print("Armenia + Azerbaijan V2Ray Config Collector")
    print(f"Target countries: {', '.join(sorted(TARGET_CCS))} "
          f"| TCP timeout: {TCP_TIMEOUT}s | Workers: {TCP_WORKERS}")
    print(sep)

    print("\n[1/3] Collecting from all sources …")
    uris = collect_all()

    print(f"\n[2/3] Verifying {len(uris)} configs (GeoIP + TCP) …")
    results = verify_all(uris)

    print(f"\n[3/3] Writing outputs …")
    write_outputs(results)

    am = sum(1 for r in results if r["country"] == "AM")
    az = sum(1 for r in results if r["country"] == "AZ")
    print(f"\n{sep}")
    print(f"Done — {len(results)} working configs total")
    print(f"       Armenia (AM):    {am}")
    print(f"       Azerbaijan (AZ): {az}")
    print(sep)


if __name__ == "__main__":
    main()
