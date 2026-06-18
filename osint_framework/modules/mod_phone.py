import requests, sys, os, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import get_key
from .base import BaseModule

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


class ModulePhone(BaseModule):
    name = "phone"
    description = "Phone lookup — NumVerify, AbstractAPI, carrier, OTX, reverse search, OSINT sources"
    target_types = ["phone"]

    def run(self, target, target_type):
        self.results = []

        # Clean the number — strip spaces, dashes, dots
        phone = re.sub(r"[\s\-\.\(\)]", "", target.strip())
        if not phone.startswith("+"):
            phone = "+" + phone.lstrip("+")

        self.emit("phone_number", phone, source="Input (normalised)")

        self._numverify(phone)
        self._abstractapi(phone)
        self._otx(phone)
        self._reverse_search(phone)
        self._truecaller_hint(phone)

        return self.results

    # ─── NumVerify — free 100/month ───────────────────────────────────────────
    def _numverify(self, phone):
        key = get_key("NUMVERIFY_KEY")
        if not key:
            self.emit("info", "NumVerify skipped — add NUMVERIFY_KEY to .env (free at numverify.com)",
                      source="NumVerify")
            return
        try:
            r = requests.get(
                "http://apilayer.net/api/validate",
                params={"access_key": key, "number": phone, "format": "1"},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("error"):
                    self.emit("error",
                              f"NumVerify: {d['error'].get('info', 'Unknown error')}",
                              source="NumVerify")
                    return
                if d.get("valid"):
                    self.emit("phone_valid",
                              f"Valid number: {d.get('international_format', phone)}",
                              source="NumVerify")
                    self.emit("location",    d.get("location", ""),     source="NumVerify")
                    self.emit("country",     d.get("country_name", ""), source="NumVerify",
                              raw={"code": d.get("country_code"), "prefix": d.get("country_prefix")})
                    self.emit("carrier",     d.get("carrier", ""),      source="NumVerify")
                    self.emit("line_type",   d.get("line_type", ""),    source="NumVerify")
                    self.emit("country_code", d.get("country_code", ""), source="NumVerify")
                else:
                    self.emit("not_found",
                              "NumVerify: Invalid or unrecognised phone number",
                              source="NumVerify")
        except Exception as e:
            self.emit("error", f"NumVerify: {e}", source="NumVerify")

    # ─── AbstractAPI — free 250/month, includes line type + carrier ───────────
    def _abstractapi(self, phone):
        key = get_key("ABSTRACTAPI_PHONE_KEY")
        if not key:
            self.emit("info",
                      "AbstractAPI skipped — add ABSTRACTAPI_PHONE_KEY to .env (free at abstractapi.com)",
                      source="AbstractAPI")
            return
        try:
            r = requests.get(
                "https://phonevalidation.abstractapi.com/v1/",
                params={"api_key": key, "phone": phone},
                headers=HEADERS, timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                valid = d.get("valid", False)
                if valid:
                    self.emit("phone_valid",
                              f"AbstractAPI: Valid — {d.get('format', {}).get('international', phone)}",
                              source="AbstractAPI")
                    # Location
                    loc = d.get("location", {})
                    if loc:
                        self.emit("location",
                                  f"{loc.get('city','')}, {loc.get('country','')}".strip(", "),
                                  source="AbstractAPI",
                                  raw=loc)
                    # Carrier
                    carrier = d.get("carrier", "")
                    if carrier:
                        self.emit("carrier", carrier, source="AbstractAPI")
                    # Line type
                    line_type = d.get("type", "")
                    if line_type:
                        self.emit("line_type", line_type, source="AbstractAPI")
                        if line_type.lower() == "voip":
                            self.emit("flag", "⚠ VOIP number — may be disposable", source="AbstractAPI")
                        if line_type.lower() == "toll_free":
                            self.emit("flag", "Toll-free number", source="AbstractAPI")
                    # Country
                    country = d.get("country", {})
                    if country:
                        self.emit("country",
                                  f"{country.get('name','')} ({country.get('code','')})",
                                  source="AbstractAPI",
                                  raw=country)
                else:
                    self.emit("not_found",
                              "AbstractAPI: Phone number is invalid",
                              source="AbstractAPI")
            elif r.status_code == 429:
                self.emit("error", "AbstractAPI: Monthly quota reached", source="AbstractAPI")
            elif r.status_code == 401:
                self.emit("error", "AbstractAPI: Invalid API key", source="AbstractAPI")
        except Exception as e:
            self.emit("error", f"AbstractAPI: {e}", source="AbstractAPI")

    # ─── AlienVault OTX — phone in threat intel ───────────────────────────────
    def _otx(self, phone):
        # Strip + for OTX search
        phone_clean = phone.lstrip("+")
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/search/pulses?q={phone_clean}",
                headers=HEADERS, timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                count = d.get("count", 0)
                if count > 0:
                    self.emit("threat_intel",
                              f"Phone found in {count} OTX threat pulse(s)",
                              source="AlienVault OTX",
                              raw={"count": count})
                    for pulse in d.get("results", [])[:5]:
                        self.emit("threat_pulse",
                                  pulse.get("name", ""),
                                  source="AlienVault OTX")
        except Exception as e:
            self.emit("error", f"OTX: {e}", source="AlienVault OTX")

    # ─── Reverse phone search via DDG ─────────────────────────────────────────
    def _reverse_search(self, phone):
        try:
            from duckduckgo_search import DDGS
            queries = [
                f'"{phone}"',
                f'"{phone}" name OR owner OR person',
                f'"{phone}" site:truecaller.com OR site:whitepages.com OR site:spokeo.com',
            ]
            seen = set()
            for q in queries:
                try:
                    with DDGS() as ddgs:
                        results = list(ddgs.text(q, max_results=5))
                    for res in results:
                        href  = res.get("href", "")
                        title = res.get("title", "")
                        body  = res.get("body", "")

                        if href and href not in seen:
                            seen.add(href)
                            domain = href.lower()

                            # Categorise by domain
                            if "truecaller.com" in domain:
                                self.emit("reverse_lookup", href, source="Truecaller (DDG)")
                            elif "whitepages.com" in domain:
                                self.emit("reverse_lookup", href, source="Whitepages (DDG)")
                            elif "spokeo.com" in domain:
                                self.emit("reverse_lookup", href, source="Spokeo (DDG)")
                            elif "yellowpages.com" in domain:
                                self.emit("reverse_lookup", href, source="YellowPages (DDG)")
                            elif "anywho.com" in domain:
                                self.emit("reverse_lookup", href, source="AnyWho (DDG)")
                            else:
                                self.emit("profile_url", href, source="Reverse Phone (DDG)")

                        # Extract name hints from title/body
                        name_match = re.search(
                            r"([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)?)\s+(?:–|-|:|\|)",
                            title
                        )
                        if name_match:
                            name = name_match.group(1)
                            if name not in seen:
                                seen.add(name)
                                self.emit("name_hint", name, source="Reverse Phone (DDG)")

                except Exception:
                    continue

        except ImportError:
            self.emit("error",
                      "duckduckgo_search not installed — run: pip install duckduckgo-search",
                      source="Reverse Phone")
        except Exception as e:
            self.emit("error", f"Reverse search: {e}", source="Reverse Phone")

    # ─── Truecaller hint (no API — just link) ─────────────────────────────────
    def _truecaller_hint(self, phone):
        """
        Truecaller has no public API, but we can emit a direct search URL
        so the analyst can click through and check manually.
        """
        phone_clean = phone.lstrip("+").replace(" ", "")
        self.emit("manual_check",
                  f"https://www.truecaller.com/search/au/{phone_clean}",
                  source="Truecaller (manual)",
                  raw={"note": "Truecaller has no public API — click to check manually"})
        # Also emit for other reverse lookup sites
        self.emit("manual_check",
                  f"https://www.whitepages.com/phone/{phone_clean}",
                  source="Whitepages (manual)")
        self.emit("manual_check",
                  f"https://www.truepeoplesearch.com/results?phoneno={phone_clean}",
                  source="TruePeopleSearch (manual)")