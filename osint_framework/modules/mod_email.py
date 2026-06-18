import re
import requests
import hashlib
import sys, os
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import get_key
from .base import BaseModule

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# Email regex
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

# Common email permutation patterns for firstname.lastname@domain
PERMUTATIONS = [
    "{f}{l}",           # johnsmith
    "{f}.{l}",          # john.smith
    "{f}_{l}",          # john_smith
    "{f}-{l}",          # john-smith
    "{f}",              # john
    "{l}",              # smith
    "{f[0]}{l}",        # jsmith
    "{f}{l[0]}",        # johns
    "{f[0]}.{l}",       # j.smith
    "{f[0]}_{l}",       # j_smith
    "{l}.{f}",          # smith.john
    "{l}{f[0]}",        # smithj
    "{l}_{f}",          # smith_john
    "{f[0]}{f[1]}{l}",  # josmith (first 2 letters)
    "{f}{l[0:3]}",      # johnsmi
]


class ModuleEmail(BaseModule):
    name = "email"
    description = "Email discovery — permutation, Hunter.io domain search, Holehe, DDG, GitHub, social"
    target_types = ["email", "people", "username", "domain"]

    def run(self, target, target_type):
        self.results = []
        target = target.strip()

        if target_type == "email":
            # Already have the email — find linked accounts and verify
            self._social_check(target)
            self._emailrep(target)
            self._ddg_email_search(target)
            self._github_email_search(target)

        elif target_type == "domain":
            # Find all emails on a domain
            self._hunter_domain(target)
            self._ddg_email_harvest(target)
            self._crtsh_emails(target)

        else:
            # people / username — try to find their email
            # Parse name parts if it looks like a full name
            parts = target.lower().split()
            if len(parts) >= 2:
                self._name_permutations(parts[0], parts[-1])
            self._ddg_email_search(target)
            self._github_username_emails(target)

        return self.results

    # ─── Social platform existence check (Holehe-style) ──────────────────────
    def _social_check(self, email):
        """
        Check if email is registered on major platforms.
        Uses password-reset/signup endpoints that leak existence.
        """
        checks = [
            {
                "name": "GitHub",
                "url": "https://api.github.com/search/users",
                "params": {"q": email},
                "found_if": lambda r: r.status_code == 200 and r.json().get("total_count", 0) > 0,
                "extract": lambda r: [u["html_url"] for u in r.json().get("items", [])[:3]]
            },
        ]

        # Platforms that expose email existence via forgot-password
        forgot_checks = [
            {
                "name": "Twitter/X",
                "url": "https://api.twitter.com/i/users/email_available.json",
                "params": {"email": email},
                "taken_if": lambda r: r.status_code == 200 and not r.json().get("valid", True),
            },
            {
                "name": "Adobe",
                "url": "https://auth.services.adobe.com/en_US/index.html#from_ims=true&old_hash=&api=authorize&nonce=",
                "method": "post",
                "data": {"username": email},
                "taken_if": lambda r: "exists" in r.text.lower(),
            },
        ]

        # GitHub user search by email
        try:
            gh_token = get_key("GITHUB_TOKEN")
            headers = {**HEADERS}
            if gh_token:
                headers["Authorization"] = f"token {gh_token}"

            r = requests.get(
                "https://api.github.com/search/users",
                params={"q": f"{email} in:email"},
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                if items:
                    for user in items[:5]:
                        self.emit("github_profile",
                                  user.get("html_url", ""),
                                  source="GitHub Email Search",
                                  raw={"login": user.get("login"), "email": email})
                        self.emit("email_found",
                                  f"Email linked to GitHub: {user.get('login')}",
                                  source="GitHub Email Search")
        except Exception as e:
            self.emit("error", f"GitHub email search: {e}", source="GitHub")

        # Gravatar — email → profile
        try:
            md5 = hashlib.md5(email.lower().encode()).hexdigest()
            r = requests.get(
                f"https://www.gravatar.com/{md5}.json",
                headers=HEADERS, timeout=8
            )
            if r.status_code == 200:
                entry = r.json().get("entry", [{}])[0]
                self.emit("email_found",
                          f"Email has Gravatar profile: {entry.get('profileUrl', '')}",
                          source="Gravatar")
                if entry.get("displayName"):
                    self.emit("full_name", entry["displayName"], source="Gravatar")
                for acct in entry.get("accounts", [])[:10]:
                    self.emit("social_profile", acct.get("url", ""),
                              source="Gravatar",
                              raw={"platform": acct.get("shortname")})
        except Exception:
            pass

    # ─── EmailRep.io — free, no key ───────────────────────────────────────────
    def _emailrep(self, email):
        try:
            r = requests.get(
                f"https://emailrep.io/{email}",
                headers={**HEADERS, "Accept": "application/json"},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                reputation  = d.get("reputation", "unknown")
                suspicious  = d.get("suspicious", False)
                references  = d.get("references", 0)
                details     = d.get("details", {})

                self.emit("email_reputation",
                          f"Reputation: {reputation} | Suspicious: {suspicious} | References: {references}",
                          source="EmailRep.io",
                          raw=d)

                if suspicious:
                    self.emit("flag", f"⚠ Email flagged suspicious by EmailRep.io", source="EmailRep.io")

                if details.get("profiles"):
                    for profile in details["profiles"][:10]:
                        self.emit("social_profile", profile, source="EmailRep.io")

                if details.get("domain_exists") is False:
                    self.emit("flag", "Email domain does not exist", source="EmailRep.io")

                if details.get("disposable"):
                    self.emit("flag", "⚠ Disposable/temp email address", source="EmailRep.io")

                if details.get("first_seen"):
                    self.emit("first_seen", details["first_seen"], source="EmailRep.io")

                if details.get("last_seen"):
                    self.emit("last_seen", details["last_seen"], source="EmailRep.io")

                if details.get("credentials_leaked"):
                    self.emit("breach_found",
                              "EmailRep: Credentials leaked in past breaches",
                              source="EmailRep.io")

                if details.get("data_breach"):
                    self.emit("breach_found",
                              "EmailRep: Found in data breaches",
                              source="EmailRep.io")

        except Exception as e:
            self.emit("error", f"EmailRep.io: {e}", source="EmailRep.io")

    # ─── Hunter.io domain search — finds all emails on a domain ──────────────
    def _hunter_domain(self, domain):
        key = get_key("HUNTER_KEY")
        if not key:
            self.emit("info",
                      "Hunter.io skipped — add HUNTER_KEY to .env (free 25/month at hunter.io)",
                      source="Hunter.io")
            return
        try:
            r = requests.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": domain, "api_key": key, "limit": 100},
                timeout=15
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                emails = d.get("emails", [])
                total  = d.get("meta", {}).get("total", 0)
                org    = d.get("organization", "")
                pattern = d.get("pattern", "")

                if org:
                    self.emit("organisation", org, source="Hunter.io")
                if pattern:
                    self.emit("email_pattern",
                              f"Email pattern: {pattern}@{domain}",
                              source="Hunter.io")
                if total:
                    self.emit("info",
                              f"Hunter.io found {total} email(s) for {domain}",
                              source="Hunter.io")

                for em in emails:
                    addr       = em.get("value", "")
                    confidence = em.get("confidence", 0)
                    fname      = em.get("first_name", "")
                    lname      = em.get("last_name", "")
                    position   = em.get("position", "")
                    sources    = len(em.get("sources", []))

                    if addr:
                        self.emit("email_address",
                                  addr,
                                  source="Hunter.io Domain Search",
                                  raw={
                                      "confidence": confidence,
                                      "name": f"{fname} {lname}".strip(),
                                      "position": position,
                                      "sources": sources
                                  })
                        if fname or lname:
                            self.emit("full_name",
                                      f"{fname} {lname}".strip(),
                                      source="Hunter.io")
                        if position:
                            self.emit("job_title", position, source="Hunter.io")

            elif r.status_code == 401:
                self.emit("error", "Hunter.io: Invalid API key", source="Hunter.io")
            elif r.status_code == 429:
                self.emit("error", "Hunter.io: Monthly quota reached", source="Hunter.io")

        except Exception as e:
            self.emit("error", f"Hunter.io: {e}", source="Hunter.io")

    # ─── DDG email search ─────────────────────────────────────────────────────
    def _ddg_email_search(self, target):
        """Search DDG for email addresses linked to a target"""
        try:
            from duckduckgo_search import DDGS
            queries = [
                f'"{target}" email',
                f'"{target}" contact email',
                f'"{target}" @gmail.com OR @yahoo.com OR @hotmail.com OR @outlook.com',
            ]
            seen = set()
            for q in queries:
                try:
                    with DDGS() as ddgs:
                        results = list(ddgs.text(q, max_results=10))
                    for r in results:
                        text = f"{r.get('title','')} {r.get('body','')}"
                        for email in EMAIL_RE.findall(text):
                            email = email.lower()
                            if email not in seen and "example" not in email:
                                seen.add(email)
                                self.emit("email_address", email,
                                          source=f"DDG Search ({target})")
                except Exception:
                    continue
        except ImportError:
            pass
        except Exception as e:
            self.emit("error", f"DDG email search: {e}", source="DDG")

    # ─── DDG email harvest from domain ───────────────────────────────────────
    def _ddg_email_harvest(self, domain):
        """Harvest all emails mentioned for a domain via DDG"""
        try:
            from duckduckgo_search import DDGS
            queries = [
                f'site:{domain} email',
                f'"@{domain}"',
                f'"{domain}" contact email staff',
            ]
            seen = set()
            for q in queries:
                try:
                    with DDGS() as ddgs:
                        results = list(ddgs.text(q, max_results=15))
                    for r in results:
                        text = f"{r.get('title','')} {r.get('body','')}"
                        for email in EMAIL_RE.findall(text):
                            email = email.lower()
                            if domain in email and email not in seen:
                                seen.add(email)
                                self.emit("email_address", email,
                                          source=f"DDG Harvest ({domain})")
                except Exception:
                    continue
        except Exception as e:
            self.emit("error", f"DDG harvest: {e}", source="DDG")

    # ─── GitHub email search ──────────────────────────────────────────────────
    def _github_email_search(self, email):
        """Search GitHub commits for an email address"""
        try:
            gh_token = get_key("GITHUB_TOKEN")
            headers = {**HEADERS}
            if gh_token:
                headers["Authorization"] = f"token {gh_token}"

            r = requests.get(
                "https://api.github.com/search/commits",
                params={"q": f"author-email:{email}", "per_page": 10},
                headers={**headers, "Accept": "application/vnd.github.cloak-preview+json"},
                timeout=10
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                seen_repos = set()
                for item in items:
                    repo = item.get("repository", {})
                    repo_url = repo.get("html_url", "")
                    author   = item.get("commit", {}).get("author", {})
                    name     = author.get("name", "")

                    if repo_url and repo_url not in seen_repos:
                        seen_repos.add(repo_url)
                        self.emit("repository", repo_url,
                                  source="GitHub Commit Search",
                                  raw={"email": email, "author": name})

                    if name:
                        self.emit("full_name", name, source="GitHub Commit Search")

        except Exception as e:
            self.emit("error", f"GitHub commit search: {e}", source="GitHub")

    # ─── GitHub username → emails ─────────────────────────────────────────────
    def _github_username_emails(self, username):
        """Find emails from GitHub commits for a username"""
        try:
            gh_token = get_key("GITHUB_TOKEN")
            headers = {**HEADERS}
            if gh_token:
                headers["Authorization"] = f"token {gh_token}"

            # Get repos
            r = requests.get(
                f"https://api.github.com/users/{username}/repos?per_page=5&sort=updated",
                headers=headers, timeout=10
            )
            if r.status_code != 200:
                return

            seen_emails = set()
            for repo in r.json()[:3]:
                repo_name = repo.get("full_name", "")
                try:
                    cr = requests.get(
                        f"https://api.github.com/repos/{repo_name}/commits?per_page=10",
                        headers=headers, timeout=10
                    )
                    if cr.status_code == 200:
                        for commit in cr.json():
                            author = commit.get("commit", {}).get("author", {})
                            email  = author.get("email", "")
                            if (email and email not in seen_emails and
                                    "noreply" not in email and
                                    "github" not in email.lower()):
                                seen_emails.add(email)
                                self.emit("email_address", email,
                                          source=f"GitHub Commit ({repo_name})",
                                          raw={"name": author.get("name", ""),
                                               "repo": repo_name})
                except Exception:
                    continue
        except Exception as e:
            self.emit("error", f"GitHub username emails: {e}", source="GitHub")

    # ─── Email permutation generator ─────────────────────────────────────────
    def _name_permutations(self, firstname, lastname):
        """
        Generate likely email addresses from a name.
        Needs Hunter.io to verify — otherwise just emits candidates.
        """
        key = get_key("HUNTER_KEY")
        f = firstname.lower()
        l = lastname.lower()

        generated = set()
        for pattern in PERMUTATIONS:
            try:
                email_local = (pattern
                    .replace("{f}", f)
                    .replace("{l}", l)
                    .replace("{f[0]}", f[0] if f else "")
                    .replace("{l[0]}", l[0] if l else "")
                    .replace("{f[1]}", f[1] if len(f) > 1 else "")
                    .replace("{f[0:2]}", f[:2])
                    .replace("{l[0:3]}", l[:3])
                )
                generated.add(email_local)
            except Exception:
                continue

        self.emit("info",
                  f"Generated {len(generated)} email permutations for {firstname} {lastname}",
                  source="Email Permutation")

        # If Hunter key available — verify each permutation against common domains
        common_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]

        if key:
            verified = []
            with ThreadPoolExecutor(max_workers=5) as ex:
                futures = {}
                for local in generated:
                    for domain in common_domains[:2]:  # limit to save quota
                        email = f"{local}@{domain}"
                        futures[ex.submit(self._hunter_verify, email, key)] = email

                for future in as_completed(futures):
                    email = futures[future]
                    try:
                        result = future.result()
                        if result:
                            verified.append(email)
                            self.emit("email_address", email,
                                      source="Hunter.io Verified Permutation",
                                      raw=result)
                    except Exception:
                        continue

            if not verified:
                # Emit as candidates if none verified
                for local in list(generated)[:10]:
                    self.emit("email_candidate",
                              f"{local}@[domain]",
                              source="Email Permutation (unverified)")
        else:
            # No Hunter key — emit top patterns as candidates
            for local in list(generated)[:8]:
                self.emit("email_candidate",
                          f"{local}@[domain] (add HUNTER_KEY to verify)",
                          source="Email Permutation")

    def _hunter_verify(self, email, key):
        """Verify a single email via Hunter.io"""
        try:
            r = requests.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": email, "api_key": key},
                timeout=8
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                if d.get("status") in ("valid", "accept_all"):
                    return d
        except Exception:
            pass
        return None

    # ─── crt.sh email extraction ──────────────────────────────────────────────
    def _crtsh_emails(self, domain):
        """Extract emails from SSL certificate transparency logs"""
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200:
                seen = set()
                for cert in r.json()[:100]:
                    issuer = cert.get("issuer_name", "")
                    name   = cert.get("name_value", "")
                    combined = f"{issuer} {name}"
                    for email in EMAIL_RE.findall(combined):
                        email = email.lower()
                        if email not in seen and domain in email:
                            seen.add(email)
                            self.emit("email_address", email,
                                      source="crt.sh Certificate Transparency")
        except Exception as e:
            self.emit("error", f"crt.sh emails: {e}", source="crt.sh")
