"""Find CDN origin-IP leaks (Akamai / Cloudflare) WITHOUT spending Censys credits.

Takes the "match a unique fingerprint on the fronted site to a non-CDN IP" logic
and sources the signals from free channels instead of Censys scans:

  - Certificate Transparency (crt.sh)      -> subdomain + historical enumeration
  - Team Cymru IP->ASN over DNS            -> classify any IP as CDN vs origin
  - Cloudflare published ranges            -> exact CF membership test
  - DNS MX / SPF(TXT)                       -> mail + ip4:/include: leaks
  - Grey-cloud detection                    -> subdomains resolving outside CDN
  - Direct vhost confirmation               -> the actual proof of origin

For each candidate non-CDN IP we open TLS to ip:443 with SNI=<domain>, send
`Host: <domain>`, and compare the leaf-cert SHA-256 / body SHA-256 / <title> /
favicon hash against the CDN-fronted baseline. A match = likely origin.

Usage:
    python3 origin_finder.py                     # reads ./targets.txt
    python3 origin_finder.py -i cr1_domains.txt -o data/cr1_origins.json
    python3 origin_finder.py -i targets.txt --no-crtsh --timeout 6

targets.txt: one apex domain per line; blank lines and #comments ignored.

NOTE: read-only recon (HTTPS GET / and /favicon.ico). Confirm every target is
in authorized scope before acting on any finding.
"""
import argparse
import concurrent.futures as cf
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from urllib.request import urlopen, Request

import dns.resolver
import dns.reversename

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")

# ASNs that mean "this IP is CDN/edge, not origin". Extend as needed.
CDN_ASNS = {
    13335,                                   # Cloudflare
    16625, 20940, 16702, 33905, 32787,       # Akamai (incl. Prolexic 32787)
    12222, 21342, 21357, 34164, 35994, 24319,  # Akamai regional
    54113,                                   # Fastly
    15133, 22606,                            # Verizon/EdgeCast
    20446,                                   # StackPath/Highwinds
    209242, 395747,                          # Cloudflare WARP / spectrum-ish
}
CDN_CNAME_HINTS = (
    "akamaiedge.net", "akamai.net", "edgekey.net", "edgesuite.net", "akadns.net",
    "cloudflare.net", "cdn.cloudflare.net", "cloudflare.com",
    "fastly.net", "edgecastcdn.net", "impervadns.net", "incapdns.net",
)
CDN_HEADER_HINTS = (
    "cf-ray", "cf-cache-status", "x-akamai", "akamai-grn", "x-cache-key",
    "x-served-by", "x-iinfo",  # fastly / incapsula
)

resolver = dns.resolver.Resolver()
resolver.lifetime = 5.0
resolver.timeout = 5.0

_cymru_cache = {}
_cf_ranges = None


# ------------------------------------------------------------------ DNS layer
def dns_query(name, rtype):
    try:
        return [r.to_text().strip('"') for r in resolver.resolve(name, rtype)]
    except Exception:
        return []


def resolve_ips(name):
    ips = set()
    for rt in ("A", "AAAA"):
        ips.update(dns_query(name, rt))
    return {i for i in ips if _is_ip(i)}


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def cnames(name):
    out = []
    try:
        ans = resolver.resolve(name, "A", raise_on_no_answer=False)
        for rr in ans.response.answer:
            if rr.rdtype == dns.rdatatype.CNAME:
                out += [t.to_text().rstrip(".") for t in rr]
    except Exception:
        pass
    return out


def ptr(ip):
    try:
        return dns_query(dns.reversename.from_address(ip).to_text(), "PTR")
    except Exception:
        return []


# -------------------------------------------------------- IP classification
def cymru_asn(ip):
    """Free IP->ASN via Team Cymru DNS. Returns (asn:int|None, asname:str)."""
    if ip in _cymru_cache:
        return _cymru_cache[ip]
    asn, name = None, ""
    try:
        if ":" in ip:  # IPv6
            rev = ipaddress.ip_address(ip).reverse_pointer.replace(".ip6.arpa", "")
            q = rev + ".origin6.asn.cymru.com"
        else:
            q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        txt = dns_query(q, "TXT")
        if txt:
            asn = int(txt[0].split("|")[0].strip().split()[0])
            an = dns_query(f"AS{asn}.asn.cymru.com", "TXT")
            if an:
                name = an[0].split("|")[-1].strip()
    except Exception:
        pass
    _cymru_cache[ip] = (asn, name)
    return asn, name


def load_cf_ranges(timeout):
    global _cf_ranges
    if _cf_ranges is not None:
        return _cf_ranges
    nets = []
    for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
        try:
            txt = urlopen(Request(url, headers={"User-Agent": "origin-finder"}), timeout=timeout).read().decode()
            nets += [ipaddress.ip_network(l.strip()) for l in txt.splitlines() if l.strip()]
        except Exception:
            pass
    _cf_ranges = nets
    return nets


def classify_ip(ip, timeout):
    """Return (is_cdn: bool, label: str)."""
    for net in load_cf_ranges(timeout):
        try:
            if ipaddress.ip_address(ip) in net:
                return True, "Cloudflare(range)"
        except ValueError:
            pass
    asn, name = cymru_asn(ip)
    if asn in CDN_ASNS:
        return True, f"AS{asn} {name}"
    up = name.upper()
    if any(x in up for x in ("AKAMAI", "CLOUDFLARE", "FASTLY", "INCAPSULA", "IMPERVA", "EDGECAST")):
        return True, f"AS{asn} {name}"
    for p in ptr(ip):
        if any(h in p for h in CDN_CNAME_HINTS):
            return True, f"ptr:{p}"
    return False, f"AS{asn} {name}" if asn else "unknown"


# ---------------------------------------------------------- HTTP fingerprint
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def https_fetch(connect_host, sni, host_header, path="/", timeout=8, verify=False):
    """Low-level: TLS to connect_host:443 with given SNI, send Host: host_header.

    Returns dict with cert_sha256, status, server, title, body_sha256, body_len.
    `verify=False` because origins often serve mismatched certs; we still capture
    the real cert fingerprint for comparison.
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    out = {"cert_sha256": None, "status": None, "server": None, "headers": {},
           "title": None, "body_sha256": None, "body_len": 0}
    try:
        raw = socket.create_connection((connect_host, 443), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            s.settimeout(timeout)
            der = s.getpeercert(binary_form=True)
            if der:
                out["cert_sha256"] = hashlib.sha256(der).hexdigest()
            req = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                   "User-Agent: Mozilla/5.0 origin-finder\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n").encode()
            s.sendall(req)
            buf = b""
            while len(buf) < 262144:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
    except Exception as e:
        out["error"] = type(e).__name__
        return out

    head, _, body = buf.partition(b"\r\n\r\n")
    head_txt = head.decode("latin-1", "replace")
    first = head_txt.split("\r\n", 1)[0]
    m = re.search(r"\s(\d{3})\s", " " + first + " ")
    out["status"] = int(m.group(1)) if m else None
    for line in head_txt.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            out["headers"][k.strip().lower()] = v.strip()
    out["server"] = out["headers"].get("server")
    # strip chunked framing crudely for hashing stability
    tm = _TITLE.search(body)
    if tm:
        out["title"] = re.sub(rb"\s+", b" ", tm.group(1)).strip().decode("utf-8", "replace")[:200]
    out["body_sha256"] = hashlib.sha256(body).hexdigest()
    out["body_len"] = len(body)
    return out


def favicon_hash(connect_host, sni, timeout):
    fx = https_fetch(connect_host, sni, sni, path="/favicon.ico", timeout=timeout)
    return fx.get("body_sha256") if fx.get("status") == 200 and fx.get("body_len", 0) > 0 else None


# ---------------------------------------------------------- candidate gather
def crtsh_subdomains(domain, timeout):
    subs = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        raw = urlopen(Request(url, headers={"User-Agent": "origin-finder"}), timeout=timeout).read()
        for row in json.loads(raw):
            for nm in str(row.get("name_value", "")).splitlines():
                nm = nm.strip().lstrip("*.").lower()
                if nm.endswith(domain) and "@" not in nm:
                    subs.add(nm)
    except Exception:
        pass
    return subs


def spf_ips_and_hosts(domain):
    ips, hosts = set(), set()
    for txt in dns_query(domain, "TXT"):
        if "v=spf1" not in txt.lower():
            continue
        for tok in txt.split():
            if tok.startswith("ip4:") or tok.startswith("ip6:"):
                net = tok.split(":", 1)[1]
                try:
                    for h in ipaddress.ip_network(net, strict=False).hosts():
                        ips.add(str(h))
                        if len(ips) > 256:
                            break
                except ValueError:
                    pass
            elif tok.startswith("a:") or tok.startswith("include:") or tok.startswith("mx:"):
                hosts.add(tok.split(":", 1)[1])
    return ips, hosts


def mx_hosts(domain):
    return {h.split()[-1].rstrip(".") for h in dns_query(domain, "MX") if h}


# ------------------------------------------------------------------- per-dom
def analyze(domain, args):
    r = {"domain": domain, "fronted_by": None, "baseline": None,
         "candidates_tested": 0, "origins": [], "notes": []}

    front_ips = resolve_ips(domain) or resolve_ips("www." + domain)
    if not front_ips:
        r["notes"].append("no A/AAAA record")
        return r

    # Is the apex actually behind a CDN?
    cdn_label = None
    for cn in cnames(domain) + cnames("www." + domain):
        if any(h in cn for h in CDN_CNAME_HINTS):
            cdn_label = f"cname:{cn}"
            break
    if not cdn_label:
        for ip in front_ips:
            is_cdn, lbl = classify_ip(ip, args.timeout)
            if is_cdn:
                cdn_label = lbl
                break
    r["fronted_by"] = cdn_label
    if not cdn_label and not args.force:
        r["notes"].append("not behind a detected CDN (grey-cloud/direct); skip. use --force to probe anyway")
        return r

    # Baseline fingerprint of the fronted site.
    base = https_fetch(domain, domain, domain, timeout=args.timeout)
    base["favicon_sha256"] = favicon_hash(domain, domain, args.timeout)
    r["baseline"] = {k: base.get(k) for k in
                     ("status", "server", "title", "cert_sha256", "body_sha256", "body_len", "favicon_sha256")}
    if not (base.get("cert_sha256") or base.get("body_sha256")):
        r["notes"].append("could not fingerprint fronted site")
        return r

    # Gather candidate hosts/IPs from free sources.
    cand_hosts = set()
    if not args.no_crtsh:
        cand_hosts |= crtsh_subdomains(domain, args.timeout)
    cand_hosts |= mx_hosts(domain)
    spf_ip, spf_hosts = spf_ips_and_hosts(domain)
    cand_hosts |= spf_hosts

    cand_ips = set(spf_ip)
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for ipset in ex.map(resolve_ips, list(cand_hosts)[: args.max_hosts]):
            cand_ips |= ipset
    cand_ips |= front_ips  # include apex IPs (catches grey-cloud)

    # Keep only non-CDN candidates (classify concurrently).
    def _classify(ip):
        is_cdn, lbl = classify_ip(ip, args.timeout)
        return None if is_cdn else (ip, lbl)
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        origin_ips = [x for x in ex.map(_classify, cand_ips) if x]
    r["candidates_tested"] = len(origin_ips)
    if not origin_ips:
        r["notes"].append(f"gathered {len(cand_ips)} IPs, all classified as CDN/edge")
        return r

    # Direct vhost confirmation against each non-CDN IP.
    def probe(item):
        ip, lbl = item
        f = https_fetch(ip, domain, domain, timeout=args.timeout)
        f["favicon_sha256"] = favicon_hash(ip, domain, args.timeout)
        score, why = 0, []
        if f.get("cert_sha256") and f["cert_sha256"] == base.get("cert_sha256"):
            score += 60; why.append("cert_sha256==")
        if f.get("body_sha256") and f["body_sha256"] == base.get("body_sha256"):
            score += 40; why.append("body_sha256==")
        if f.get("title") and f["title"] == base.get("title") and base.get("title"):
            score += 20; why.append("title==")
        if f.get("favicon_sha256") and f["favicon_sha256"] == base.get("favicon_sha256"):
            score += 25; why.append("favicon==")
        return {"ip": ip, "asn": lbl, "status": f.get("status"), "server": f.get("server"),
                "title": f.get("title"), "cert_sha256": f.get("cert_sha256"),
                "score": score, "match": why, "error": f.get("error")}

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(probe, origin_ips))
    results.sort(key=lambda x: x["score"], reverse=True)
    r["origins"] = [x for x in results if x["score"] >= args.min_score] or results[:5]
    return r


# ------------------------------------------------------------------- driver
def read_targets(path):
    doms = []
    with open(path) as fh:
        for line in fh:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                d = re.sub(r"^https?://", "", line).split("/")[0].strip()
                if d:
                    doms.append(d)
    return list(dict.fromkeys(doms))


def main():
    ap = argparse.ArgumentParser(description="Find CDN origin-IP leaks without Censys credits.")
    ap.add_argument("-i", "--input", default=os.path.join(HERE, "targets.txt"))
    ap.add_argument("-o", "--output", default=os.path.join(DATA, "origin_findings.json"))
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--workers", type=int, default=16, help="concurrent IP probes per domain")
    ap.add_argument("--max-hosts", type=int, default=200, help="cap crt.sh subdomains resolved")
    ap.add_argument("--min-score", type=int, default=40, help="report threshold (cert=60, body=40)")
    ap.add_argument("--no-crtsh", action="store_true", help="skip crt.sh enumeration")
    ap.add_argument("--force", action="store_true", help="probe even if no CDN detected")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        sys.exit(f"input not found: {args.input} (create targets.txt, one domain per line)")
    targets = read_targets(args.input)
    os.makedirs(DATA, exist_ok=True)
    print(f"[*] {len(targets)} targets from {args.input}\n", file=sys.stderr)

    findings = []
    for i, dom in enumerate(targets, 1):
        t0 = time.time()
        try:
            res = analyze(dom, args)
        except Exception as e:
            res = {"domain": dom, "error": f"{type(e).__name__}: {e}"}
        findings.append(res)
        hits = res.get("origins", [])
        top = hits[0] if hits and hits[0].get("score", 0) >= args.min_score else None
        flag = f"ORIGIN {top['ip']} (score {top['score']} {','.join(top['match'])})" if top else \
               res.get("notes", [""])[0] if res.get("notes") else "no match"
        print(f"[{i}/{len(targets)}] {dom:40s} cdn={res.get('fronted_by')!s:22s} "
              f"cand={res.get('candidates_tested',0):3d} -> {flag}  ({time.time()-t0:.1f}s)",
              file=sys.stderr)

    with open(args.output, "w") as fh:
        json.dump(findings, fh, indent=2)
    confirmed = sum(1 for f in findings
                    if any(o.get("score", 0) >= args.min_score for o in f.get("origins", [])))
    print(f"\n[*] wrote {args.output}  |  {confirmed}/{len(targets)} with likely origin", file=sys.stderr)


if __name__ == "__main__":
    main()
