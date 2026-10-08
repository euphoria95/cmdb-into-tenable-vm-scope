# cmdb-into-tenable-vm-scope

Turn a raw CMDB / asset FQDN list into a **triaged vulnerability-scan scope** so
Tenable (or any scanner) only spends cycles on real, customer-owned attack
surface — never on a WAF/CDN edge, a third-party SaaS host, or a broken DNS
record.

## The problem

Point a scanner at a WAF/CDN-fronted hostname and it scans the **edge**, not your
asset:

- Findings are attributed to **Cloudflare / Akamai / Imperva**, not to you —
  false risk on someone else's infrastructure.
- Scan cycles are wasted on shared edge IPs you don't own.
- It can breach the CDN provider's acceptable-use policy.

The same waste happens when an FQDN resolves to a shared SaaS platform (Wix,
Vercel, Shopify…), a shared parking/redirect box, or a bogus DNS record
(`127.0.0.1`, `8.8.8.8`, dangling CNAME).

`vm_triage.py` classifies every FQDN up front and tells the scanner what to do
with it — using only **free data sources, no paid API credits**.

## Verdicts

| Verdict | Meaning | Scanner action |
|---|---|---|
| `SCAN` | Direct customer IP, no WAF | Scan the FQDN — real surface |
| `SCAN_ORIGIN` | WAF-fronted **but** the origin IP was found | Scan `origin_ip`, not the FQDN |
| `SKIP_EDGE` | WAF/CDN edge (Cloudflare, Akamai, Imperva, Fastly, CloudFront, Azure Front Door, Sucuri, …) | Drop — findings would be the provider's |
| `SKIP_SAAS` | Third-party SaaS/PaaS (Wix, Vercel, Netlify, Shopify, GitHub/GitLab Pages, HubSpot, …) | Drop — not customer-owned |
| `SHARED_HOST` | ≥N in-scope FQDNs on one IP, all bare redirect/empty/503 (shared parking/redirect) | Scan the IP **once**, not per-FQDN |
| `INVESTIGATE` | No A/AAAA, dangling CNAME, or non-routable/placeholder record | Fix DNS / check for subdomain takeover, then remove |

Every row carries a plain-language `reason`, so the verdict is auditable.

## How it classifies (all free)

- **DNS** — A/AAAA/CNAME/MX/TXT resolution.
- **Team Cymru IP→ASN over DNS** (`origin.asn.cymru.com`) — classify any IP as
  CDN/edge vs. customer, no API key.
- **Cloudflare published ranges** — exact membership test.
- **Live HTTP/TLS fingerprint** — status, `Server`, WAF headers (`cf-ray`,
  `x-akamai`, `x-iinfo`, `x-amz-cf-id`, `x-azure-ref`…), page title, leaf-cert
  SHA-256.
- **SaaS signatures** — CNAME, server header, parking-title, known shared-IP
  prefixes.
- **Batch relation** — shared-IP clustering across the input list.

## Install

```bash
pip install -r requirements.txt   # dnspython, requests
```

## Usage

```bash
# Fast classify-only (recommended for routine scope triage)
python3 vm_triage.py -i targets.txt -o vm_triage.csv --no-origin-hunt

# Also hunt leaked origins behind WAFs -> upgrades SKIP_EDGE to SCAN_ORIGIN
python3 vm_triage.py -i targets.txt -o vm_triage.csv --origin-hunt

# Tuning
--shared-threshold N   # min in-scope FQDNs on one IP to call it SHARED_HOST (default 3)
--use-spf              # include SPF ip4:/include: hosts in origin hunt (mail-infra noise; off by default)
--no-crtsh             # skip crt.sh enumeration during origin hunt
--timeout 6 --workers 24
```

Input: plain FQDN list, one per line (`#` comments and blank lines ignored). See
`example_targets.txt`.

### Output columns (`vm_triage.csv`)

`fqdn, verdict, reason, waf_provider, resolved_ips, asn, origin_ip, origin_evidence, http_status, title`

## `origin_finder.py` (companion)

Standalone aggressive origin-leak hunter, and the shared detection core that
`vm_triage.py` imports. Given CDN-fronted domains, it gathers candidate IPs from
Certificate Transparency (crt.sh), DNS/MX/SPF, and grey-cloud records, filters
out CDN-owned space via ASN, then **confirms** an origin by connecting directly
to the candidate IP with `SNI=<domain>` + `Host: <domain>` and matching the
leaf-cert / body / title / favicon against the fronted baseline.

```bash
python3 origin_finder.py -i targets.txt -o origin_findings.json
```

## Scope & limitations

- Read-only recon: HTTPS `GET /` and `/favicon.ico` only. No auth, no writes to
  targets. **Only run against assets you are authorized to assess.**
- WAF detection for Akamai relies on ASN + CNAME/header hints (Akamai publishes
  no IP list); Cloudflare membership is exact.
- A WAF with no telltale header on a non-dedicated ASN can fall through to
  `SCAN` — the `reason` column makes this transparent.
- Finds candidates and confirms by live content match. **Forgotten/historical
  A-records** no longer in DNS or CT are the one gap — that's where a paid source
  (e.g. Censys) still earns its place, used only on the residual.

## License

MIT
