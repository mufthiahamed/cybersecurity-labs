import socket
import requests
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import get_key
from .base import BaseModule

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# Subdomain takeover fingerprints
TAKEOVER_FINGERPRINTS = {
    "github.io":           "There isn't a GitHub Pages site here",
    "amazonaws.com":       "NoSuchBucket",
    "heroku.com":          "No such app",
    "shopify.com":         "Sorry, this shop is currently unavailable",
    "fastly.net":          "Fastly error: unknown domain",
    "pantheon.io":         "The gods are wise",
    "wordpress.com":       "Do you want to register",
    "tumblr.com":          "Whatever you were looking for doesn't currently exist",
    "ghost.io":            "The thing you were looking for is no longer here",
    "surge.sh":            "project not found",
    "bitbucket.io":        "Repository not found",
    "readthedocs.io":      "unknown to Read the Docs",
    "zendesk.com":         "Help Center Closed",
    "netlify.com":         "Not Found - Request ID",
}


class ModuleWHOIS(BaseModule):
    name = "whois"
    description = "WHOIS, DNS, crt.sh, SecurityTrails, ViewDNS, Whoxy, takeover detection"
    target_types = ["domain"]

    def run(self, target, target_type):
        self.results = []
        domain = target.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]

        self._dns_resolve(domain)
        self._rdap(domain)
        self._full_dns(domain)
        self._crtsh(domain)
        self._securitytrails(domain)
        self._viewdns(domain)
        self._whoxy(domain)
        self._takeover_check(domain)

        return self.results

    # ─── DNS Resolution ───────────────────────────────────────────────────────
    def _dns_resolve(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            self.emit("ip_address", ip, source="DNS Resolution",
                      raw={"domain": domain})
        except Exception as e:
            self.emit("error", f"DNS resolution failed: {e}", source="DNS Resolution")

        # Also get all A records via Google DNS
        try:
            r = requests.get(
                f"https://dns.google/resolve?name={domain}&type=A",
                headers=HEADERS, timeout=8
            )
            if r.status_code == 200:
                for ans in r.json().get("Answer", []):
                    self.emit("a_record", ans.get("data", ""), source="Google DNS")
        except Exception:
            pass

    # ─── RDAP WHOIS ───────────────────────────────────────────────────────────
    def _rdap(self, domain):
        try:
            r = requests.get(f"https://rdap.org/domain/{domain}",
                             headers=HEADERS, timeout=10)
            if r.status_code == 200:
                d = r.json()

                # Registrar + registrant
                for entity in d.get("entities", []):
                    roles  = entity.get("roles", [])
                    vcard  = entity.get("vcardArray", [])
                    handle = entity.get("handle", "")
                    vdata  = vcard[1] if vcard and len(vcard) > 1 else []

                    fn    = next((v[3] for v in vdata if v[0] == "fn"), "")
                    email = next((v[3] for v in vdata if v[0] == "email"), "")
                    org   = next((v[3] for v in vdata if v[0] == "org"), "")
                    tel   = next((v[3] for v in vdata if v[0] == "tel"), "")
                    adr   = next((v[3] for v in vdata if v[0] == "adr"), "")

                    if "registrar" in roles:
                        self.emit("registrar", fn or handle, source="RDAP WHOIS")
                    if "registrant" in roles:
                        if fn:    self.emit("registrant_name",  fn,    source="RDAP WHOIS")
                        if email: self.emit("registrant_email", email, source="RDAP WHOIS")
                        if org:   self.emit("registrant_org",   org,   source="RDAP WHOIS")
                        if tel:   self.emit("registrant_phone", tel,   source="RDAP WHOIS")
                        if adr:   self.emit("registrant_addr",  str(adr), source="RDAP WHOIS")

                # Dates
                for event in d.get("events", []):
                    action = event.get("eventAction", "")
                    date   = event.get("eventDate", "")[:10]
                    if action == "registration":
                        self.emit("registered_date", date, source="RDAP WHOIS")
                    elif action == "expiration":
                        self.emit("expiry_date", date, source="RDAP WHOIS")
                    elif action == "last changed":
                        self.emit("updated_date", date, source="RDAP WHOIS")

                # Nameservers
                for ns in d.get("nameservers", []):
                    self.emit("nameserver", ns.get("ldhName", ""), source="RDAP WHOIS")

                # Status
                for s in d.get("status", []):
                    self.emit("domain_status", s, source="RDAP WHOIS")

        except Exception as e:
            self.emit("error", f"RDAP WHOIS: {e}", source="RDAP WHOIS")

    # ─── Full DNS Records via Google DNS ──────────────────────────────────────
    def _full_dns(self, domain):
        record_types = {
            "MX":    "mx_record",
            "TXT":   "txt_record",
            "NS":    "nameserver",
            "AAAA":  "aaaa_record",
            "CNAME": "cname_record",
            "SOA":   "soa_record",
            "CAA":   "caa_record",
        }
        for rtype, emit_type in record_types.items():
            try:
                r = requests.get(
                    f"https://dns.google/resolve?name={domain}&type={rtype}",
                    headers=HEADERS, timeout=8
                )
                if r.status_code == 200:
                    for ans in r.json().get("Answer", []):
                        data = ans.get("data", "").strip('"')
                        if data:
                            self.emit(emit_type, f"{rtype}: {data}", source="Google DNS")
                            # Flag interesting TXT records
                            if rtype == "TXT":
                                if "v=spf1" in data:
                                    self.emit("spf_record", data, source="DNS TXT")
                                if "v=DMARC1" in data:
                                    self.emit("dmarc_record", data, source="DNS TXT")
                                if "google-site-verification" in data:
                                    self.emit("google_verified", data, source="DNS TXT")
                                if "MS=" in data:
                                    self.emit("microsoft_verified", data, source="DNS TXT")
            except Exception:
                continue

    # ─── Certificate Transparency (crt.sh) ───────────────────────────────────
    def _crtsh(self, domain):
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200:
                seen = set()
                emails = set()
                for cert in r.json()[:100]:
                    # Subdomains
                    name = cert.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and sub not in seen and domain in sub and not sub.startswith("*"):
                            seen.add(sub)
                            self.emit("subdomain", sub, source="crt.sh")

                    # Issuer emails sometimes exposed
                    issuer = cert.get("issuer_name", "")
                    if "@" in issuer:
                        import re
                        for em in re.findall(r"[\w.+-]+@[\w.-]+\.\w+", issuer):
                            if em not in emails:
                                emails.add(em)
                                self.emit("email", em, source="crt.sh (cert issuer)")

        except Exception as e:
            self.emit("error", f"crt.sh: {e}", source="crt.sh")

    # ─── SecurityTrails — free 50/month ───────────────────────────────────────
    def _securitytrails(self, domain):
        key = get_key("SECURITYTRAILS_KEY")
        if not key:
            self.emit("info",
                      "SecurityTrails skipped — add SECURITYTRAILS_KEY to .env (free at securitytrails.com)",
                      source="SecurityTrails")
            return
        try:
            headers = {**HEADERS, "APIKEY": key}

            # Domain info
            r = requests.get(
                f"https://api.securitytrails.com/v1/domain/{domain}",
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                # Current DNS
                dns = d.get("current_dns", {})
                for rtype, records in dns.items():
                    for rec in records.get("values", []):
                        val = rec.get("ip") or rec.get("nameserver") or rec.get("value") or ""
                        if val:
                            self.emit(f"{rtype.lower()}_record", val, source="SecurityTrails")
                # Registrar info
                if d.get("registrar_name"):
                    self.emit("registrar", d["registrar_name"], source="SecurityTrails")
                if d.get("whois", {}).get("registrant"):
                    reg = d["whois"]["registrant"]
                    if reg.get("email"):
                        self.emit("registrant_email", reg["email"], source="SecurityTrails WHOIS")

            # Historical DNS — shows old IPs, great for tracking
            r2 = requests.get(
                f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                headers=headers, timeout=10
            )
            if r2.status_code == 200:
                records = r2.json().get("records", [])
                for rec in records[:10]:
                    for val in rec.get("values", []):
                        ip = val.get("ip", "")
                        first = rec.get("first_seen", "")
                        last  = rec.get("last_seen", "")
                        if ip:
                            self.emit("historical_ip",
                                      f"{ip} (seen: {first} → {last})",
                                      source="SecurityTrails History")

            # Subdomains
            r3 = requests.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                headers=headers, timeout=10
            )
            if r3.status_code == 200:
                subs = r3.json().get("subdomains", [])
                for sub in subs[:50]:
                    self.emit("subdomain", f"{sub}.{domain}", source="SecurityTrails")

        except Exception as e:
            self.emit("error", f"SecurityTrails: {e}", source="SecurityTrails")

    # ─── ViewDNS — free, no key ───────────────────────────────────────────────
    def _viewdns(self, domain):
        try:
            # Reverse IP lookup — find other domains on same server
            r = requests.get(
                f"https://viewdns.info/api/reverseip/?host={domain}&apikey=&output=json",
                headers=HEADERS, timeout=10
            )
            if r.status_code == 200:
                try:
                    d = r.json()
                    domains = d.get("response", {}).get("domains", [])
                    count   = d.get("response", {}).get("domain_count", 0)
                    if count:
                        self.emit("reverse_ip_count",
                                  f"{count} domains on same IP",
                                  source="ViewDNS Reverse IP")
                    for dom in domains[:20]:
                        name = dom.get("name", "")
                        if name:
                            self.emit("shared_hosting_domain", name, source="ViewDNS Reverse IP")
                except Exception:
                    pass

            # IP History — shows old IPs for domain
            r2 = requests.get(
                f"https://viewdns.info/api/iphistory/?domain={domain}&apikey=&output=json",
                headers=HEADERS, timeout=10
            )
            if r2.status_code == 200:
                try:
                    records = r2.json().get("response", {}).get("records", [])
                    for rec in records[:10]:
                        ip       = rec.get("ip", "")
                        location = rec.get("location", "")
                        owner    = rec.get("owner", "")
                        lastseen = rec.get("lastseen", "")
                        if ip:
                            self.emit("historical_ip",
                                      f"{ip} — {owner} — {location} (last: {lastseen})",
                                      source="ViewDNS IP History")
                except Exception:
                    pass

        except Exception as e:
            self.emit("error", f"ViewDNS: {e}", source="ViewDNS")

    # ─── Whoxy — free 100/month ───────────────────────────────────────────────
    def _whoxy(self, domain):
        key = get_key("WHOXY_KEY")
        if not key:
            self.emit("info",
                      "Whoxy skipped — add WHOXY_KEY to .env (free at whoxy.com)",
                      source="Whoxy")
            return
        try:
            r = requests.get(
                "https://api.whoxy.com/",
                params={"key": key, "whois": domain},
                headers=HEADERS, timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == 1:
                    reg = d.get("registrant_contact", {})
                    if reg.get("full_name"):
                        self.emit("registrant_name",  reg["full_name"],  source="Whoxy")
                    if reg.get("email_address"):
                        self.emit("registrant_email", reg["email_address"], source="Whoxy")
                    if reg.get("company_name"):
                        self.emit("registrant_org",   reg["company_name"],  source="Whoxy")
                    if reg.get("phone_number"):
                        self.emit("registrant_phone", reg["phone_number"],  source="Whoxy")
                    if reg.get("mailing_address"):
                        self.emit("registrant_addr",  reg["mailing_address"], source="Whoxy")

                    # Dates
                    if d.get("create_date"):
                        self.emit("registered_date", d["create_date"], source="Whoxy")
                    if d.get("expiry_date"):
                        self.emit("expiry_date", d["expiry_date"], source="Whoxy")
                    if d.get("update_date"):
                        self.emit("updated_date", d["update_date"], source="Whoxy")

                    # Registrar
                    registrar = d.get("domain_registrar", {})
                    if registrar.get("registrar_name"):
                        self.emit("registrar", registrar["registrar_name"], source="Whoxy")

        except Exception as e:
            self.emit("error", f"Whoxy: {e}", source="Whoxy")

    # ─── Subdomain Takeover Detection ─────────────────────────────────────────
    def _takeover_check(self, domain):
        """
        Check if any subdomains found are vulnerable to takeover.
        Looks for CNAME pointing to unclaimed services.
        """
        # Get CNAME records
        try:
            r = requests.get(
                f"https://dns.google/resolve?name={domain}&type=CNAME",
                headers=HEADERS, timeout=8
            )
            if r.status_code == 200:
                cnames = [a.get("data", "") for a in r.json().get("Answer", [])]
                for cname in cnames:
                    for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                        if service in cname:
                            # Check if the target actually responds with the error
                            try:
                                resp = requests.get(
                                    f"http://{domain}",
                                    headers=HEADERS, timeout=8,
                                    allow_redirects=True
                                )
                                if fingerprint.lower() in resp.text.lower():
                                    self.emit("takeover_vulnerable",
                                              f"⚠ POSSIBLE SUBDOMAIN TAKEOVER: {domain} → {cname} ({service})",
                                              source="Takeover Check",
                                              raw={"cname": cname, "service": service})
                            except Exception:
                                pass
        except Exception:
            pass