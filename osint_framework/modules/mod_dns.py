import socket
import requests
from .base import BaseModule

class ModuleDNS(BaseModule):
    name = "dns"
    description = "DNS record enumeration — A, MX, TXT, NS records"
    target_types = ["domain"]

    def run(self, target, target_type):
        self.results = []
        domain = target.lower().strip()

        # Use Google DNS-over-HTTPS (free, no key)
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
        for rtype in record_types:
            try:
                r = requests.get(
                    f"https://dns.google/resolve?name={domain}&type={rtype}",
                    timeout=8
                )
                if r.status_code == 200:
                    data = r.json()
                    for answer in data.get("Answer", []):
                        val = answer.get("data", "").strip().rstrip(".")
                        if val:
                            self.emit(f"dns_{rtype.lower()}", val, source=f"Google DNS ({rtype})")
            except Exception as e:
                self.emit("error", f"DNS {rtype} failed: {e}", source="Google DNS")

        # SPF / DMARC check
        for prefix in ["", "_dmarc.", "_domainkey."]:
            try:
                r = requests.get(
                    f"https://dns.google/resolve?name={prefix}{domain}&type=TXT",
                    timeout=8
                )
                if r.status_code == 200:
                    for answer in r.json().get("Answer", []):
                        val = answer.get("data", "")
                        if "v=spf" in val.lower():
                            self.emit("spf_record", val.strip('"'), source="DNS TXT")
                        if "v=dmarc" in val.lower():
                            self.emit("dmarc_record", val.strip('"'), source="DNS TXT")
            except:
                pass

        return self.results
