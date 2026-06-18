import requests
import socket
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import get_key
from .base import BaseModule

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


class ModuleIP(BaseModule):
    name = "ip"
    description = "IP geolocation, ASN, abuse, threat intel — ipapi, IPinfo, AbuseIPDB, Shodan, Censys, OTX, GreyNoise"
    target_types = ["ip", "domain"]

    def run(self, target, target_type):
        self.results = []

        # Resolve domain → IP first
        if target_type == "domain":
            try:
                resolved = socket.gethostbyname(target)
                self.emit("ip_address", resolved, source="DNS Resolution",
                          raw={"domain": target})
                target = resolved
            except Exception as e:
                self.emit("error", f"Could not resolve domain to IP: {e}", source="IP Module")
                return self.results

        self._ipapi(target)
        self._ipinfo(target)
        self._abuseipdb(target)
        self._shodan(target)
        self._censys(target)
        self._alienvault(target)
        self._greynoise(target)
        self._virustotal(target)

        return self.results

    # ─── ipapi.co — free, no key ──────────────────────────────────────────────
    def _ipapi(self, ip):
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/",
                             headers=HEADERS, timeout=10)
            if r.status_code == 200:
                d = r.json()
                if d.get("error"):
                    return
                self.emit("ip_address",  d.get("ip", ""),       source="ipapi.co")
                self.emit("location",
                          f"{d.get('city','')}, {d.get('region','')}, {d.get('country_name','')}",
                          source="ipapi.co",
                          raw={"city": d.get("city"), "region": d.get("region"),
                               "country": d.get("country_name"), "country_code": d.get("country_code")})
                self.emit("isp_org",     d.get("org", ""),       source="ipapi.co")
                self.emit("asn",         d.get("asn", ""),       source="ipapi.co")
                self.emit("timezone",    d.get("timezone", ""),  source="ipapi.co")
                self.emit("coordinates",
                          f"{d.get('latitude')}, {d.get('longitude')}",
                          source="ipapi.co",
                          raw={"lat": d.get("latitude"), "lon": d.get("longitude")})
                if d.get("postal"):
                    self.emit("postal_code", d.get("postal"), source="ipapi.co")
                if d.get("currency"):
                    self.emit("currency", d.get("currency"), source="ipapi.co")
        except Exception as e:
            self.emit("error", f"ipapi.co: {e}", source="ipapi.co")

    # ─── IPinfo — free 50k/month, richer data ─────────────────────────────────
    def _ipinfo(self, ip):
        key = get_key("IPINFO_KEY")
        try:
            params = {"token": key} if key else {}
            r = requests.get(f"https://ipinfo.io/{ip}/json",
                             params=params, headers=HEADERS, timeout=10)
            if r.status_code == 200:
                d = r.json()
                if d.get("bogon"):
                    self.emit("info", "IP is a bogon/private address", source="IPinfo")
                    return
                if d.get("hostname"):
                    self.emit("hostname", d.get("hostname"), source="IPinfo")
                if d.get("org"):
                    self.emit("isp_org", d.get("org"), source="IPinfo")
                if d.get("abuse"):
                    abuse = d["abuse"]
                    self.emit("abuse_contact",
                              f"{abuse.get('name','')} — {abuse.get('email','')} — {abuse.get('phone','')}",
                              source="IPinfo Abuse")
                if d.get("privacy"):
                    priv = d["privacy"]
                    flags = []
                    if priv.get("vpn"):     flags.append("VPN")
                    if priv.get("proxy"):   flags.append("Proxy")
                    if priv.get("tor"):     flags.append("Tor")
                    if priv.get("hosting"): flags.append("Hosting/DC")
                    if flags:
                        self.emit("privacy_flag", " | ".join(flags), source="IPinfo Privacy")
                if d.get("domains"):
                    for domain in d["domains"].get("domains", [])[:10]:
                        self.emit("hosted_domain", domain, source="IPinfo Domains")
        except Exception as e:
            self.emit("error", f"IPinfo: {e}", source="IPinfo")

    # ─── AbuseIPDB — free 1k/day with key ────────────────────────────────────
    def _abuseipdb(self, ip):
        key = get_key("ABUSEIPDB_KEY")
        if not key:
            self.emit("info", "AbuseIPDB skipped — add ABUSEIPDB_KEY to .env (free at abuseipdb.com)",
                      source="AbuseIPDB")
            return
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": key, "Accept": "application/json"},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                score     = d.get("abuseConfidenceScore", 0)
                reports   = d.get("totalReports", 0)
                last_seen = d.get("lastReportedAt", "never")
                domain    = d.get("domain", "")
                usage     = d.get("usageType", "")
                isp       = d.get("isp", "")
                is_tor    = d.get("isTor", False)
                is_public = d.get("isPublic", True)

                self.emit("abuse_score",
                          f"{score}% confidence malicious | {reports} reports | Last: {last_seen}",
                          source="AbuseIPDB",
                          raw={"score": score, "reports": reports, "last_seen": last_seen})
                if domain:
                    self.emit("hostname", domain, source="AbuseIPDB")
                if usage:
                    self.emit("usage_type", usage, source="AbuseIPDB")
                if isp:
                    self.emit("isp_org", isp, source="AbuseIPDB")
                if is_tor:
                    self.emit("privacy_flag", "Tor exit node", source="AbuseIPDB")
                if score >= 50:
                    self.emit("threat_intel",
                              f"HIGH RISK IP — {score}% abuse confidence",
                              source="AbuseIPDB")

                # Recent reports
                for report in d.get("reports", [])[:5]:
                    cats = report.get("categories", [])
                    self.emit("abuse_report",
                              f"Reported: {report.get('reportedAt','')} — Categories: {cats}",
                              source="AbuseIPDB")
            elif r.status_code == 422:
                self.emit("error", "AbuseIPDB: Invalid IP format", source="AbuseIPDB")
            elif r.status_code == 429:
                self.emit("error", "AbuseIPDB: Daily limit reached", source="AbuseIPDB")
        except Exception as e:
            self.emit("error", f"AbuseIPDB: {e}", source="AbuseIPDB")

    # ─── Shodan — free 100 queries/month ──────────────────────────────────────
    def _shodan(self, ip):
        key = get_key("SHODAN_KEY")
        if not key:
            self.emit("info", "Shodan skipped — add SHODAN_KEY to .env (free at shodan.io)",
                      source="Shodan")
            return
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": key},
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200:
                d = r.json()
                # Open ports
                ports = d.get("ports", [])
                if ports:
                    self.emit("open_ports",
                              f"Open ports: {', '.join(str(p) for p in ports)}",
                              source="Shodan", raw={"ports": ports})
                # Hostnames
                for h in d.get("hostnames", []):
                    self.emit("hostname", h, source="Shodan")
                # Domains
                for dom in d.get("domains", []):
                    self.emit("hosted_domain", dom, source="Shodan")
                # OS
                if d.get("os"):
                    self.emit("os_detected", d.get("os"), source="Shodan")
                # Country
                if d.get("country_name"):
                    self.emit("location", d.get("country_name"), source="Shodan")
                # CVEs / vulns
                vulns = d.get("vulns", [])
                if vulns:
                    self.emit("vulnerabilities",
                              f"CVEs found: {', '.join(list(vulns)[:10])}",
                              source="Shodan", raw={"cves": list(vulns)})
                # Banners / services
                for item in d.get("data", [])[:10]:
                    port    = item.get("port")
                    product = item.get("product", "")
                    version = item.get("version", "")
                    banner  = item.get("data", "")[:200]
                    self.emit("service_banner",
                              f"Port {port} — {product} {version}".strip(),
                              source="Shodan",
                              raw={"port": port, "product": product,
                                   "version": version, "banner": banner})
            elif r.status_code == 404:
                self.emit("info", "Shodan: No data for this IP", source="Shodan")
            elif r.status_code == 401:
                self.emit("error", "Shodan: Invalid API key", source="Shodan")
        except Exception as e:
            self.emit("error", f"Shodan: {e}", source="Shodan")

    # ─── Censys — free 250 queries/month ──────────────────────────────────────
    def _censys(self, ip):
        api_id     = get_key("CENSYS_API_ID")
        api_secret = get_key("CENSYS_API_SECRET")
        if not api_id or not api_secret:
            self.emit("info", "Censys skipped — add CENSYS_API_ID + CENSYS_API_SECRET to .env (free at censys.io)",
                      source="Censys")
            return
        try:
            r = requests.get(
                f"https://search.censys.io/api/v2/hosts/{ip}",
                auth=(api_id, api_secret),
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200:
                d = r.json().get("result", {})
                # Location
                loc = d.get("location", {})
                if loc:
                    self.emit("location",
                              f"{loc.get('city','')}, {loc.get('country','')}",
                              source="Censys",
                              raw=loc)
                # ASN
                asn = d.get("autonomous_system", {})
                if asn:
                    self.emit("asn",
                              f"AS{asn.get('asn','')} — {asn.get('name','')} ({asn.get('country_code','')})",
                              source="Censys")
                # Services / ports
                for svc in d.get("services", [])[:10]:
                    port     = svc.get("port")
                    proto    = svc.get("transport_protocol", "")
                    svc_name = svc.get("service_name", "")
                    product  = svc.get("software", [{}])[0].get("product", "") if svc.get("software") else ""
                    self.emit("service_banner",
                              f"Port {port}/{proto} — {svc_name} {product}".strip(),
                              source="Censys",
                              raw={"port": port, "proto": proto, "service": svc_name})
                # TLS certs
                for svc in d.get("services", []):
                    tls = svc.get("tls", {})
                    cert = tls.get("certificates", {}).get("leaf_data", {})
                    names = cert.get("names", [])
                    for name in names[:5]:
                        self.emit("ssl_cert_name", name, source="Censys TLS")
            elif r.status_code == 404:
                self.emit("info", "Censys: No data for this IP", source="Censys")
            elif r.status_code == 403:
                self.emit("error", "Censys: Invalid credentials", source="Censys")
        except Exception as e:
            self.emit("error", f"Censys: {e}", source="Censys")

    # ─── AlienVault OTX — free, no key ────────────────────────────────────────
    def _alienvault(self, ip):
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers=HEADERS, timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                pulse_count = d.get("pulse_info", {}).get("count", 0)
                if pulse_count > 0:
                    self.emit("threat_intel",
                              f"Found in {pulse_count} OTX threat pulse(s)",
                              source="AlienVault OTX",
                              raw={"pulses": pulse_count})
                    # Pulse names
                    for pulse in d.get("pulse_info", {}).get("pulses", [])[:5]:
                        self.emit("threat_pulse",
                                  pulse.get("name", ""),
                                  source="AlienVault OTX")
                reputation = d.get("reputation", 0)
                if reputation:
                    self.emit("reputation_score", str(reputation), source="AlienVault OTX")
                # Country from OTX
                country = d.get("country_name", "")
                if country:
                    self.emit("location", country, source="AlienVault OTX")
        except Exception as e:
            self.emit("error", f"AlienVault OTX: {e}", source="AlienVault OTX")

    # ─── GreyNoise — free community tier ──────────────────────────────────────
    def _greynoise(self, ip):
        key = get_key("GREYNOISE_KEY")
        try:
            headers = {**HEADERS, "key": key} if key else HEADERS
            r = requests.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                noise        = d.get("noise", False)
                riot         = d.get("riot", False)
                classification = d.get("classification", "")
                name         = d.get("name", "")
                message      = d.get("message", "")

                if noise:
                    self.emit("threat_intel",
                              f"GreyNoise: Internet scanner/noise — {classification} — {name}",
                              source="GreyNoise",
                              raw=d)
                if riot:
                    self.emit("info",
                              f"GreyNoise RIOT: Known benign service — {name}",
                              source="GreyNoise")
                if message and not noise and not riot:
                    self.emit("info", f"GreyNoise: {message}", source="GreyNoise")
            elif r.status_code == 404:
                self.emit("info", "GreyNoise: IP not in dataset", source="GreyNoise")
            elif r.status_code == 429:
                self.emit("error", "GreyNoise: Rate limited", source="GreyNoise")
        except Exception as e:
            self.emit("error", f"GreyNoise: {e}", source="GreyNoise")

    # ─── VirusTotal — free 500 lookups/day ────────────────────────────────────
    def _virustotal(self, ip):
        key = get_key("VIRUSTOTAL_KEY")
        if not key:
            self.emit("info", "VirusTotal skipped — add VIRUSTOTAL_KEY to .env (free at virustotal.com)",
                      source="VirusTotal")
            return
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={**HEADERS, "x-apikey": key},
                timeout=10
            )
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious  = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless   = stats.get("harmless", 0)

                self.emit("vt_analysis",
                          f"Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless}",
                          source="VirusTotal",
                          raw=stats)
                if malicious > 0:
                    self.emit("threat_intel",
                              f"VirusTotal: Flagged malicious by {malicious} engine(s)",
                              source="VirusTotal")

                # Categories
                categories = attrs.get("categories", {})
                if categories:
                    cats = list(set(categories.values()))[:5]
                    self.emit("ip_category", ", ".join(cats), source="VirusTotal")

                # Country
                country = attrs.get("country", "")
                if country:
                    self.emit("location", country, source="VirusTotal")

            elif r.status_code == 401:
                self.emit("error", "VirusTotal: Invalid API key", source="VirusTotal")
            elif r.status_code == 429:
                self.emit("error", "VirusTotal: Rate limit exceeded", source="VirusTotal")
        except Exception as e:
            self.emit("error", f"VirusTotal: {e}", source="VirusTotal")
