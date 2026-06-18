import requests, hashlib, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import get_key
from .base import BaseModule

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

class ModuleBreach(BaseModule):
    name = "breach"
    description = "Check email against breach databases, HIBP, Hunter.io, Gravatar, MX validation"
    target_types = ["email"]

    def run(self, target, target_type):
        self.results = []
        email = target.strip().lower()

        self._leakcheck(email)
        self._hibp(email)
        self._hunter(email)
        self._gravatar(email)
        self._mx_check(email)

        return self.results

    # ─── LeakCheck ────────────────────────────────────────────────────────────
    def _leakcheck(self, email):
        key = get_key("LEAKCHECK_KEY")
        try:
            if key:
                r = requests.get(
                    "https://leakcheck.io/api/v2/query/" + email,
                    headers={"X-API-Key": key}, timeout=10
                )
            else:
                r = requests.get(
                    f"https://leakcheck.io/api/public?check={email}",
                    headers=HEADERS, timeout=10
                )
            if r.status_code == 200:
                d = r.json()
                count = d.get("found", 0)
                if count > 0:
                    self.emit("breach_found", f"Found in {count} breach(es)", source="LeakCheck.io")
                    for src in d.get("sources", [])[:20]:
                        name = src.get("name", src) if isinstance(src, dict) else src
                        self.emit("breach_source", str(name), source="LeakCheck.io")
                else:
                    self.emit("breach_clean", "No breaches found", source="LeakCheck.io")
        except Exception as e:
            self.emit("error", f"LeakCheck: {e}", source="LeakCheck.io")

    # ─── HaveIBeenPwned ───────────────────────────────────────────────────────
    # Free tier: breach list only (no paste, no passwords). Key required for v3.
    def _hibp(self, email):
        key = get_key("HIBP_KEY")
        try:
            headers = {**HEADERS, "hibp-api-key": key} if key else HEADERS
            # Breaches
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                breaches = r.json()
                self.emit(
                    "breach_found",
                    f"HIBP: Found in {len(breaches)} breach(es)",
                    source="HaveIBeenPwned"
                )
                for b in breaches:
                    detail = (
                        f"{b.get('Name')} ({b.get('BreachDate', 'unknown date')}) — "
                        f"{b.get('PwnCount', 0):,} accounts — "
                        f"Data: {', '.join(b.get('DataClasses', []))}"
                    )
                    self.emit("breach_source", detail, source="HaveIBeenPwned",
                              raw={"breach": b.get("Name"), "date": b.get("BreachDate"),
                                   "count": b.get("PwnCount"), "data": b.get("DataClasses")})
            elif r.status_code == 404:
                self.emit("breach_clean", "HIBP: No breaches found", source="HaveIBeenPwned")
            elif r.status_code == 401:
                self.emit("error", "HIBP: API key required — get one free at haveibeenpwned.com/API/Key", source="HaveIBeenPwned")
            elif r.status_code == 429:
                self.emit("error", "HIBP: Rate limited — slow down requests", source="HaveIBeenPwned")

            # Pastes (requires key)
            if key:
                r2 = requests.get(
                    f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                    headers=headers, timeout=10
                )
                if r2.status_code == 200:
                    pastes = r2.json()
                    self.emit(
                        "paste_found",
                        f"HIBP: Found in {len(pastes)} paste(s)",
                        source="HaveIBeenPwned"
                    )
                    for p in pastes[:10]:
                        self.emit("paste_source",
                                  f"{p.get('Source')} — {p.get('Title', 'untitled')} ({p.get('Date', 'unknown')})",
                                  source="HaveIBeenPwned",
                                  raw=p)

        except Exception as e:
            self.emit("error", f"HIBP: {e}", source="HaveIBeenPwned")

    # ─── Hunter.io ────────────────────────────────────────────────────────────
    # Free tier: 25 searches/month. Get key at hunter.io
    def _hunter(self, email):
        key = get_key("HUNTER_KEY")
        if not key:
            self.emit("info", "Hunter.io skipped — add HUNTER_KEY to .env for email verification", source="Hunter.io")
            return
        try:
            r = requests.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": email, "api_key": key},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                status   = d.get("status", "unknown")       # valid / invalid / disposable / webmail
                score    = d.get("score", 0)                # deliverability 0–100
                disposable = d.get("disposable", False)
                webmail    = d.get("webmail", False)
                mx_found   = d.get("mx_records", False)
                smtp_ok    = d.get("smtp_server", False)

                self.emit("email_verified",
                          f"Status: {status} | Score: {score}/100 | Disposable: {disposable} | Webmail: {webmail}",
                          source="Hunter.io",
                          raw=d)

                if disposable:
                    self.emit("email_disposable", "Email uses a disposable/temp domain", source="Hunter.io")
                if not mx_found:
                    self.emit("mx_invalid", "Hunter: No MX records found for domain", source="Hunter.io")
                if not smtp_ok:
                    self.emit("smtp_fail", "Hunter: SMTP server check failed", source="Hunter.io")

            elif r.status_code == 401:
                self.emit("error", "Hunter.io: Invalid API key", source="Hunter.io")
            elif r.status_code == 429:
                self.emit("error", "Hunter.io: Monthly quota reached", source="Hunter.io")

        except Exception as e:
            self.emit("error", f"Hunter.io: {e}", source="Hunter.io")

    # ─── Gravatar ─────────────────────────────────────────────────────────────
    def _gravatar(self, email):
        try:
            md5 = hashlib.md5(email.encode()).hexdigest()
            r = requests.get(f"https://www.gravatar.com/{md5}.json",
                             headers=HEADERS, timeout=8)
            if r.status_code == 200:
                entry = r.json().get("entry", [{}])[0]
                if entry.get("displayName"):
                    self.emit("full_name", entry["displayName"], source="Gravatar")
                if entry.get("profileUrl"):
                    self.emit("profile_url", entry["profileUrl"], source="Gravatar")
                if entry.get("thumbnailUrl"):
                    self.emit("avatar_url", entry["thumbnailUrl"], source="Gravatar")
                for acct in entry.get("accounts", [])[:10]:
                    self.emit("social_profile", acct.get("url", ""), source="Gravatar",
                              raw={"platform": acct.get("shortname")})
                for email_entry in entry.get("emails", []):
                    val = email_entry.get("value", "")
                    if val and val != email:
                        self.emit("email_alias", val, source="Gravatar")
        except Exception:
            pass

    # ─── MX / Domain Check ────────────────────────────────────────────────────
    def _mx_check(self, email):
        try:
            domain = email.split("@")[1]
            self.emit("email_domain", domain, source="Email Parser")

            # MX records
            r = requests.get(
                f"https://dns.google/resolve?name={domain}&type=MX",
                headers=HEADERS, timeout=8
            )
            if r.status_code == 200:
                answers = r.json().get("Answer", [])
                if answers:
                    self.emit("mx_valid",
                              f"Domain has {len(answers)} MX record(s): "
                              + ", ".join(a.get("data", "") for a in answers[:3]),
                              source="DNS MX Check")
                else:
                    self.emit("mx_invalid", "No MX records — domain may not receive email", source="DNS MX Check")

            # TXT records (SPF / DMARC)
            r2 = requests.get(
                f"https://dns.google/resolve?name={domain}&type=TXT",
                headers=HEADERS, timeout=8
            )
            if r2.status_code == 200:
                txt_records = r2.json().get("Answer", [])
                for rec in txt_records:
                    data = rec.get("data", "")
                    if "v=spf1" in data:
                        self.emit("spf_record", data, source="DNS TXT Check")
                    if "v=DMARC1" in data:
                        self.emit("dmarc_record", data, source="DNS TXT Check")

            # DMARC subdomain
            r3 = requests.get(
                f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT",
                headers=HEADERS, timeout=8
            )
            if r3.status_code == 200:
                dmarc = r3.json().get("Answer", [])
                for rec in dmarc:
                    self.emit("dmarc_record", rec.get("data", ""), source="DNS DMARC Check")

        except Exception as e:
            self.emit("error", f"DNS check: {e}", source="Email Parser")