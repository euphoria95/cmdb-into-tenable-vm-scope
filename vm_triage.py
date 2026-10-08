"""VM scope triage / enrichment engine for Tenable (or any) vuln-scan asset lists.

Problem it solves: scanning a WAF/CDN-fronted FQDN scans the Cloudflare/Akamai
EDGE, not the asset. You get the provider's CVEs (false attribution), waste scan
cycles, and may breach the provider's ToS. This engine classifies each FQDN so
the scanner only spends effort on real, customer-owned attack surface.

Input : plain FQDN list, one per line (# comments / blanks ignored).
Output: annotated CSV (keeps every input row) with columns:
    fqdn, verdict, reason, waf_provider, resolved_ips, asn, origin_ip,
    origin_evidence, http_status, title

Verdicts:
    SCAN         resolves to a customer IP, no WAF -> scan normally
    SCAN_ORIGIN  WAF-fronted but a real origin IP was found -> scan origin_ip
    SKIP_EDGE    WAF/CDN-fronted, no origin found -> findings would be provider's
    DROP_CDN_IP  FQDN resolves straight to CDN-owned space, no WAF headers
    INVESTIGATE  no A/AAAA (dangling / possible subdomain takeover)

Reuses the detection core from origin_finder.py (DNS, Team Cymru ASN, Cloudflare
ranges, TLS/HTTP fingerprint, crt.sh). No Censys credits consumed.

Usage:
    python3 vm_triage.py -i targets.txt -o data/vm_triage.csv
    python3 vm_triage.py -i cr1_domains.txt --origin-hunt --use-spf
    python3 vm_triage.py -i targets.txt --no-origin-hunt   # just classify, fast
"""
import argparse
import collections
import concurrent.futures as cf
import csv
import ipaddress
import os
import sys

import origin_finder as of  # shared detection core

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")

# Obvious placeholder A-records that are never a real asset (public resolvers etc.).
PLACEHOLDER_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "0.0.0.0"}


def is_bogon(ip):
    """Non-routable / reserved / placeholder -> a bad DNS record, not a scan target."""
    if ip in PLACEHOLDER_IPS:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (a.is_private or a.is_loopback or a.is_reserved
            or a.is_link_local or a.is_unspecified or a.is_multicast)

# WAF/CDN provider signatures. ASN used only where the AS is dedicated edge
# (never for AWS/Azure general compute, which would drop legit customer assets).
WAF_SIGS = [
    ("Cloudflare",        {"cname": ("cloudflare.net", "cdn.cloudflare.net"),
                           "hdr": ("cf-ray", "cf-cache-status"), "server": ("cloudflare",),
                           "asn": {13335}}),
    ("Akamai",            {"cname": ("akamaiedge.net", "edgekey.net", "edgesuite.net",
                                     "akamai.net", "akadns.net"),
                           "hdr": ("x-akamai", "akamai-grn", "x-akamai-transformed"),
                           "server": ("akamaighost", "akamai"),
                           "asn": {16625, 20940, 16702, 33905, 32787, 12222, 21342,
                                   21357, 34164, 35994, 24319}}),
    ("Imperva/Incapsula", {"cname": ("incapdns.net", "impervadns.net"),
                           "hdr": ("x-iinfo", "x-cdn"), "server": ("incapsula",), "asn": set()}),
    ("Fastly",            {"cname": ("fastly.net",), "hdr": ("x-served-by", "x-fastly"),
                           "server": ("varnish",), "asn": {54113}}),
    ("AWS CloudFront",    {"cname": ("cloudfront.net",), "hdr": ("x-amz-cf-id", "x-amz-cf-pop"),
                           "server": ("cloudfront",), "asn": set()}),
    ("Azure Front Door",  {"cname": ("azurefd.net", "azureedge.net", "trafficmanager.net"),
                           "hdr": ("x-azure-ref", "x-fd-int-roxy-purgeid"), "server": (), "asn": set()}),
    ("Sucuri",            {"cname": ("sucuri.net",), "hdr": ("x-sucuri-id", "x-sucuri-cache"),
                           "server": ("sucuri",), "asn": set()}),
    ("Google Cloud",      {"cname": ("ghs.googlehosted.com",), "hdr": ("via",),
                           "server": ("google frontend", "gfe"), "asn": set()}),
]


# Third-party SaaS/PaaS hosting. Asset lives on a shared platform the customer
# doesn't own -> scanning it hits the provider, not customer surface. Signatures
# kept tight (cname / server header / parking-title) to avoid false positives on
# real apps that merely mention a brand.
SAAS_SIGS = [
    ("Wix",            {"cname": ("wixdns.net", "wix.com"), "server": ("pepyaka",),
                        "title": ("wix.com", "connectyourdomain"),
                        "ippfx": ("23.236.62.", "23.236.56.", "185.230.63.", "185.230.60.")}),
    ("Squarespace",    {"cname": ("squarespace.com",), "server": ("squarespace",),
                        "title": ("squarespace",), "ippfx": ("198.185.159.", "198.49.23.", "198.185.158.", "198.49.22.")}),
    ("Shopify",        {"cname": ("myshopify.com", "shops.myshopify.com", "shopify.com"),
                        "server": ("shopify",), "title": ("this shop is currently unavailable",), "ippfx": ()}),
    ("GitHub Pages",   {"cname": ("github.io", "github.map.fastly.net"), "server": ("github.com",),
                        "title": (), "ippfx": ("185.199.108.", "185.199.109.", "185.199.110.", "185.199.111.")}),
    ("GitLab Pages",   {"cname": ("gitlab.io",), "server": (), "title": (), "ippfx": ()}),
    ("Vercel",         {"cname": ("vercel.app", "vercel-dns.com"), "server": ("vercel",),
                        "title": (), "ippfx": ("76.76.21.",)}),
    ("Netlify",        {"cname": ("netlify.app", "netlify.com"), "server": ("netlify",),
                        "title": (), "ippfx": ("75.2.60.", "99.83.190.")}),
    ("HubSpot",        {"cname": ("hubspot.net", "hs-sites.com", "hubspotusercontent"),
                        "server": ("hubspot", "cos"), "title": (), "ippfx": ()}),
    ("Webflow",        {"cname": ("proxy-ssl.webflow.com", "webflow.io"), "server": (),
                        "title": (), "ippfx": ()}),
    ("Firebase/Google", {"cname": ("web.app", "firebaseapp.com", "googleusercontent.com", "ghs.google"),
                         "server": (), "title": (), "ippfx": ()}),
    ("WordPress.com",  {"cname": ("wordpress.com", "wpengine.com"), "server": (), "title": (), "ippfx": ()}),
    ("AWS S3 website", {"cname": ("s3-website", "s3.amazonaws.com"), "server": ("amazons3",),
                        "title": (), "ippfx": ()}),
]


def detect_saas(cnames, headers, title, ips):
    """Return SaaS/PaaS platform name if the FQDN is hosted on one, else None."""
    cn_blob = " ".join(cnames).lower()
    server = headers.get("server", "").lower()
    t = (title or "").lower()
    for name, sig in SAAS_SIGS:
        if any(c in cn_blob for c in sig["cname"]):
            return name
        if any(s in server for s in sig["server"]):
            return name
        if any(x in t for x in sig["title"]):
            return name
        if any(ip.startswith(p) for ip in ips for p in sig["ippfx"]):
            return name
    return None


def detect_waf(cnames, headers, ips, timeout):
    """Return provider name if FQDN is WAF/CDN-fronted, else None."""
    hdr_keys = {k.lower() for k in headers}
    hdr_blob = " ".join(f"{k}:{v}".lower() for k, v in headers.items())
    server = headers.get("server", "").lower()
    cn_blob = " ".join(cnames).lower()
    asns = {of.cymru_asn(ip)[0] for ip in ips}

    for name, sig in WAF_SIGS:
        if any(c in cn_blob for c in sig["cname"]):
            return name
        if any(h in hdr_keys for h in sig["hdr"]):
            return name
        if any(s in server for s in sig["server"]):
            return name
        if sig["asn"] & asns:
            return name
    return None


def triage(fqdn, args):
    row = {"fqdn": fqdn, "verdict": "", "reason": "", "waf_provider": "",
           "resolved_ips": "", "asn": "", "origin_ip": "", "origin_evidence": "",
           "http_status": "", "title": ""}

    ips = of.resolve_ips(fqdn) or of.resolve_ips("www." + fqdn)
    cns = of.cnames(fqdn) + of.cnames("www." + fqdn)
    row["resolved_ips"] = ",".join(sorted(ips))

    if not ips:
        row["verdict"] = "INVESTIGATE"
        row["reason"] = ("dangling CNAME -> " + cns[0]) if cns else "no A/AAAA record"
        return row

    # Reject bad DNS records before any connection (localhost, private, placeholder).
    routable = {ip for ip in ips if not is_bogon(ip)}
    if not routable:
        row["verdict"] = "INVESTIGATE"
        row["reason"] = f"non-routable/placeholder A-record (bad DNS): {','.join(sorted(ips))}"
        return row
    ips = routable

    # Fingerprint the fronted site (also yields live headers for WAF detection).
    base = of.https_fetch(fqdn, fqdn, fqdn, timeout=args.timeout)
    row["http_status"] = base.get("status") or ""
    row["title"] = base.get("title") or ""
    asns = {of.cymru_asn(ip) for ip in ips}
    row["asn"] = "; ".join(sorted(f"AS{a} {n}".strip() for a, n in asns if a)) or "unknown"

    headers = base.get("headers", {})
    waf = detect_waf(cns, headers, ips, args.timeout)
    row["waf_provider"] = waf or ""

    # Third-party SaaS/PaaS hosting wins: scanning it hits the provider either way.
    saas = detect_saas(cns, headers, base.get("title"), ips)
    if saas:
        row["verdict"] = "SKIP_SAAS"
        row["reason"] = f"hosted on {saas} (shared SaaS/PaaS) -> not customer scan surface"
        return row

    # No WAF: is the IP itself CDN-owned (edge infra) or a real customer asset?
    if not waf:
        cdn_ip = any(of.classify_ip(ip, args.timeout)[0] for ip in ips)
        if cdn_ip:
            row["verdict"] = "DROP_CDN_IP"
            row["reason"] = "resolves into CDN-owned space, no WAF headers; scanning edge is useless"
        else:
            row["verdict"] = "SCAN"
            row["reason"] = "direct customer IP, no WAF -> real scan surface"
        return row

    # WAF present. Optionally hunt the origin so the scan can target it directly.
    if not args.origin_hunt:
        row["verdict"] = "SKIP_EDGE"
        row["reason"] = f"{waf}-fronted; origin hunt disabled"
        return row

    origin = hunt_origin(fqdn, base, args)
    if origin:
        row["verdict"] = "SCAN_ORIGIN"
        row["origin_ip"] = origin["ip"]
        row["origin_evidence"] = f"score {origin['score']}: {','.join(origin['match'])}"
        row["reason"] = f"{waf}-fronted but origin leaked -> scan origin_ip"
    else:
        row["verdict"] = "SKIP_EDGE"
        row["reason"] = f"{waf}-fronted, no origin found -> findings would be provider's"
    return row


def hunt_origin(fqdn, base, args):
    """Return best non-CDN IP whose content matches the fronted baseline, or None."""
    if not (base.get("cert_sha256") or base.get("body_sha256")):
        return None
    hosts = set()
    if not args.no_crtsh:
        hosts |= of.crtsh_subdomains(fqdn, args.timeout)
    hosts |= of.mx_hosts(fqdn)
    cand = set(of.resolve_ips(fqdn))
    if args.use_spf:
        spf_ip, spf_hosts = of.spf_ips_and_hosts(fqdn)
        cand |= spf_ip
        hosts |= spf_hosts
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for ipset in ex.map(of.resolve_ips, list(hosts)[: args.max_hosts]):
            cand |= ipset

    def _nonedge(ip):
        return None if of.classify_ip(ip, args.timeout)[0] else ip
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        origins = [ip for ip in ex.map(_nonedge, cand) if ip]
    if not origins:
        return None

    bfav = of.favicon_hash(fqdn, fqdn, args.timeout)

    def _probe(ip):
        f = of.https_fetch(ip, fqdn, fqdn, timeout=args.timeout)
        score, why = 0, []
        if f.get("cert_sha256") and f["cert_sha256"] == base.get("cert_sha256"):
            score += 60; why.append("cert==")
        if f.get("body_sha256") and f["body_sha256"] == base.get("body_sha256"):
            score += 40; why.append("body==")
        if f.get("title") and base.get("title") and f["title"] == base["title"]:
            score += 20; why.append("title==")
        if bfav and of.favicon_hash(ip, fqdn, args.timeout) == bfav:
            score += 25; why.append("favicon==")
        return {"ip": ip, "score": score, "match": why}

    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        best = max(ex.map(_probe, origins), key=lambda x: x["score"])
    return best if best["score"] >= args.min_score else None


PARKING_STATUS = {"301", "302", "303", "307", "308", "503", ""}


def mark_shared_hosts(rows, threshold):
    """Batch pass: an IP serving >=threshold in-scope FQDNs with only bare
    redirects/empty/503 responses is shared parking/redirect infra, not per-FQDN
    scan surface. Reclassify those rows to SHARED_HOST (scan the IP once instead).
    A shared IP serving real distinct content (titled 200s) is left as SCAN.
    """
    byip = collections.defaultdict(list)
    for r in rows:
        if r["verdict"] == "SCAN":
            for ip in r["resolved_ips"].split(","):
                if ip:
                    byip[ip].append(r)
    for ip, group in byip.items():
        if len(group) < threshold:
            continue
        parked = [r for r in group if str(r["http_status"]) in PARKING_STATUS and not r["title"]]
        if len(parked) < threshold:
            continue  # shared, but serves real content -> keep as SCAN
        for r in parked:
            r["verdict"] = "SHARED_HOST"
            r["reason"] = (f"IP {ip} serves {len(group)} in-scope FQDNs, bare redirect/empty "
                           "-> shared parking/redirect; scan the IP once, not per-FQDN")


def read_targets(path):
    out = []
    with open(path) as fh:
        for line in fh:
            s = line.strip().lower()
            if s and not s.startswith("#"):
                s = __import__("re").sub(r"^https?://", "", s).split("/")[0].strip()
                if s:
                    out.append(s)
    return list(dict.fromkeys(out))


def main():
    ap = argparse.ArgumentParser(description="Triage/enrich a VM scan scope: which FQDNs are real surface vs WAF edge.")
    ap.add_argument("-i", "--input", default=os.path.join(HERE, "targets.txt"))
    ap.add_argument("-o", "--output", default=os.path.join(DATA, "vm_triage.csv"))
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--max-hosts", type=int, default=150, help="cap crt.sh subdomains resolved during origin hunt")
    ap.add_argument("--min-score", type=int, default=40, help="origin confirm threshold (cert=60, body=40)")
    ap.add_argument("--shared-threshold", type=int, default=3, help="min in-scope FQDNs on one IP (all parked/redirect) to call it SHARED_HOST")
    ap.add_argument("--origin-hunt", dest="origin_hunt", action="store_true", default=True,
                    help="for WAF-fronted FQDNs, try to find the origin (default on)")
    ap.add_argument("--no-origin-hunt", dest="origin_hunt", action="store_false",
                    help="classify only; don't hunt origins (much faster)")
    ap.add_argument("--use-spf", action="store_true", help="include SPF ip4:/include: hosts in origin hunt (mail-infra noise; off by default)")
    ap.add_argument("--no-crtsh", action="store_true", help="skip crt.sh enumeration in origin hunt")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        sys.exit(f"input not found: {args.input}")
    targets = read_targets(args.input)
    os.makedirs(DATA, exist_ok=True)
    print(f"[*] triaging {len(targets)} FQDNs (origin_hunt={args.origin_hunt}, spf={args.use_spf})\n", file=sys.stderr)

    cols = ["fqdn", "verdict", "reason", "waf_provider", "resolved_ips", "asn",
            "origin_ip", "origin_evidence", "http_status", "title"]
    rows = []
    for i, dom in enumerate(targets, 1):
        try:
            r = triage(dom, args)
        except Exception as e:
            r = {c: "" for c in cols}
            r["fqdn"] = dom; r["verdict"] = "ERROR"; r["reason"] = f"{type(e).__name__}: {e}"
        rows.append(r)
        print(f"[{i}/{len(targets)}] {dom:38s} {r['verdict']:12s} {r.get('waf_provider',''):18s} "
              f"{('origin=' + r['origin_ip']) if r.get('origin_ip') else r['reason'][:46]}", file=sys.stderr)

    mark_shared_hosts(rows, args.shared_threshold)  # batch-relational pass

    with open(args.output, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    tally = {}
    for r in rows:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print("\n[*] verdict tally: " + "  ".join(f"{k}={v}" for k, v in sorted(tally.items())), file=sys.stderr)
    scan = tally.get("SCAN", 0) + tally.get("SCAN_ORIGIN", 0)
    print(f"[*] {scan}/{len(targets)} worth scanning; wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
