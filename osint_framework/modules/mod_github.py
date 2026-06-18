import requests
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import get_key
from .base import BaseModule

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


class ModuleGitHub(BaseModule):
    name = "github"
    description = "GitHub profile, repos, commit emails, orgs, gists, FullContact, Clearbit enrichment"
    target_types = ["username", "domain", "email"]

    def run(self, target, target_type):
        self.results = []

        # If domain, strip to org name; if email, extract username part
        if target_type == "domain":
            query = target.split(".")[0]
        elif target_type == "email":
            query = target.split("@")[0]
        else:
            query = target.strip().lstrip("@")

        github_token = get_key("GITHUB_TOKEN")
        headers = {**HEADERS}
        if github_token:
            headers["Authorization"] = f"token {github_token}"

        self._profile(query, headers)
        self._repos(query, headers)
        self._commit_emails(query, headers)
        self._orgs(query, headers)
        self._gists(query, headers)
        self._events(query, headers)
        self._search_code(query, headers)

        return self.results

    # ─── Profile ──────────────────────────────────────────────────────────────
    def _profile(self, username, headers):
        try:
            r = requests.get(
                f"https://api.github.com/users/{username}",
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                self.emit("profile_url",
                          f"https://github.com/{d.get('login')}",
                          source="GitHub API")
                if d.get("name"):
                    self.emit("full_name", d["name"], source="GitHub API", raw=d)
                if d.get("email"):
                    self.emit("email_address", d["email"], source="GitHub API")
                    # Enrich email with FullContact + Clearbit
                    self._fullcontact(d["email"])
                    self._clearbit(d["email"])
                if d.get("location"):
                    self.emit("location", d["location"], source="GitHub API")
                if d.get("company"):
                    self.emit("company",
                              d["company"].lstrip("@"),
                              source="GitHub API")
                if d.get("blog"):
                    self.emit("website", d["blog"], source="GitHub API")
                if d.get("bio"):
                    self.emit("bio", d["bio"], source="GitHub API")
                if d.get("twitter_username"):
                    self.emit("social_profile",
                              f"https://twitter.com/{d['twitter_username']}",
                              source="GitHub API")
                if d.get("hireable"):
                    self.emit("flag", "User is open to hire", source="GitHub API")

                self.emit("stat",
                          f"Public repos: {d.get('public_repos', 0)} | "
                          f"Followers: {d.get('followers', 0)} | "
                          f"Following: {d.get('following', 0)} | "
                          f"Gists: {d.get('public_gists', 0)}",
                          source="GitHub API")
                self.emit("account_created",
                          d.get("created_at", "")[:10],
                          source="GitHub API")
                self.emit("account_updated",
                          d.get("updated_at", "")[:10],
                          source="GitHub API")

                # Avatar
                if d.get("avatar_url"):
                    self.emit("avatar_url", d["avatar_url"], source="GitHub API")

                # Account type
                acct_type = d.get("type", "User")
                self.emit("account_type", acct_type, source="GitHub API")

            elif r.status_code == 404:
                self.emit("not_found",
                          f"No GitHub account for '{username}'",
                          source="GitHub API")
            elif r.status_code == 403:
                self.emit("error",
                          "GitHub API rate limited — add GITHUB_TOKEN to .env for higher limits",
                          source="GitHub API")
        except Exception as e:
            self.emit("error", f"GitHub profile: {e}", source="GitHub API")

    # ─── Repos ────────────────────────────────────────────────────────────────
    def _repos(self, username, headers):
        try:
            r = requests.get(
                f"https://api.github.com/users/{username}/repos"
                f"?per_page=30&sort=updated&type=owner",
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                repos = r.json()
                # Sort by stars
                repos.sort(key=lambda x: x.get("stargazers_count", 0), reverse=True)

                languages = set()
                topics    = set()

                for repo in repos:
                    stars = repo.get("stargazers_count", 0)
                    forks = repo.get("forks_count", 0)
                    desc  = repo.get("description", "") or ""
                    lang  = repo.get("language", "") or ""
                    is_fork = repo.get("fork", False)

                    if lang:
                        languages.add(lang)

                    for topic in repo.get("topics", []):
                        topics.add(topic)

                    label = f"⭐{stars} 🍴{forks}"
                    if is_fork:
                        label += " [fork]"

                    self.emit("repository",
                              repo["html_url"],
                              source="GitHub API",
                              raw={
                                  "stars": stars,
                                  "forks": forks,
                                  "desc": desc,
                                  "language": lang,
                                  "fork": is_fork,
                                  "label": label
                              })

                if languages:
                    self.emit("languages_used",
                              ", ".join(sorted(languages)),
                              source="GitHub API")
                if topics:
                    self.emit("repo_topics",
                              ", ".join(sorted(topics)),
                              source="GitHub API")

        except Exception as e:
            self.emit("error", f"GitHub repos: {e}", source="GitHub API")

    # ─── Commit Email Extraction ───────────────────────────────────────────────
    # GitHub exposes commit author emails in the commit API even if hidden on profile
    def _commit_emails(self, username, headers):
        found_emails = set()
        try:
            # Get repos to check
            r = requests.get(
                f"https://api.github.com/users/{username}/repos?per_page=10&sort=updated",
                headers=headers, timeout=10
            )
            if r.status_code != 200:
                return

            for repo in r.json()[:5]:
                if repo.get("fork"):
                    continue
                repo_name = repo.get("full_name", "")
                try:
                    commits_r = requests.get(
                        f"https://api.github.com/repos/{repo_name}/commits?per_page=10",
                        headers=headers, timeout=10
                    )
                    if commits_r.status_code == 200:
                        for commit in commits_r.json():
                            author = commit.get("commit", {}).get("author", {})
                            email  = author.get("email", "")
                            name   = author.get("name", "")
                            if (email and
                                    email not in found_emails and
                                    "noreply" not in email and
                                    "github" not in email.lower()):
                                found_emails.add(email)
                                self.emit("email_address",
                                          email,
                                          source=f"GitHub Commit ({repo_name})",
                                          raw={"name": name, "repo": repo_name})
                                # Enrich newly found email
                                self._fullcontact(email)
                                self._clearbit(email)
                except Exception:
                    continue

        except Exception as e:
            self.emit("error", f"GitHub commit emails: {e}", source="GitHub Commits")

    # ─── Organisations ────────────────────────────────────────────────────────
    def _orgs(self, username, headers):
        try:
            r = requests.get(
                f"https://api.github.com/users/{username}/orgs",
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                for org in r.json():
                    self.emit("organisation",
                              f"https://github.com/{org.get('login')}",
                              source="GitHub API",
                              raw={"name": org.get("login"),
                                   "desc": org.get("description", "")})
        except Exception as e:
            self.emit("error", f"GitHub orgs: {e}", source="GitHub API")

    # ─── Gists ────────────────────────────────────────────────────────────────
    def _gists(self, username, headers):
        try:
            r = requests.get(
                f"https://api.github.com/users/{username}/gists?per_page=10",
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                for gist in r.json():
                    desc = gist.get("description", "") or "untitled"
                    url  = gist.get("html_url", "")
                    files = list(gist.get("files", {}).keys())
                    self.emit("gist",
                              url,
                              source="GitHub Gists",
                              raw={"desc": desc, "files": files})

                    # Check gist content for emails/secrets (raw file)
                    for fname, fdata in gist.get("files", {}).items():
                        raw_url = fdata.get("raw_url", "")
                        if raw_url and fdata.get("size", 0) < 50000:
                            try:
                                import re
                                content_r = requests.get(raw_url, headers=headers, timeout=8)
                                if content_r.status_code == 200:
                                    text = content_r.text
                                    # Emails in gist content
                                    for em in re.findall(r"[\w.+-]+@[\w.-]+\.\w+", text):
                                        if "noreply" not in em:
                                            self.emit("email_address", em,
                                                      source=f"GitHub Gist ({fname})")
                                    # Possible secrets/keys
                                    secret_patterns = [
                                        (r"(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[=:]\s*[\'\"]?([A-Za-z0-9_\-]{16,})", "possible_secret"),
                                        (r"(?i)AIza[0-9A-Za-z\-_]{35}", "google_api_key"),
                                        (r"(?i)sk-[A-Za-z0-9]{48}", "openai_key"),
                                        (r"(?i)ghp_[A-Za-z0-9]{36}", "github_token"),
                                        (r"(?i)AKIA[0-9A-Z]{16}", "aws_access_key"),
                                    ]
                                    for pattern, label in secret_patterns:
                                        for match in re.findall(pattern, text):
                                            val = match if isinstance(match, str) else match[-1]
                                            self.emit(label, val[:60],
                                                      source=f"GitHub Gist ({fname})")
                            except Exception:
                                continue
        except Exception as e:
            self.emit("error", f"GitHub gists: {e}", source="GitHub Gists")

    # ─── Public Events ────────────────────────────────────────────────────────
    def _events(self, username, headers):
        """Extract additional emails and activity from public events"""
        try:
            r = requests.get(
                f"https://api.github.com/users/{username}/events/public?per_page=30",
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                seen_emails = set()
                for event in r.json():
                    payload = event.get("payload", {})
                    # PushEvent → commit emails
                    for commit in payload.get("commits", []):
                        author = commit.get("author", {})
                        email  = author.get("email", "")
                        if (email and email not in seen_emails and
                                "noreply" not in email and "github" not in email.lower()):
                            seen_emails.add(email)
                            self.emit("email_address", email,
                                      source="GitHub Events (push commit)",
                                      raw={"name": author.get("name", "")})
        except Exception as e:
            self.emit("error", f"GitHub events: {e}", source="GitHub Events")

    # ─── Code Search ──────────────────────────────────────────────────────────
    def _search_code(self, username, headers):
        """Search GitHub code for username mentions — finds linked accounts"""
        try:
            r = requests.get(
                f"https://api.github.com/search/users?q={username}&per_page=5",
                headers=headers, timeout=10
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                for item in items:
                    login = item.get("login", "")
                    if login.lower() != username.lower():
                        self.emit("related_account",
                                  f"https://github.com/{login}",
                                  source="GitHub User Search",
                                  raw={"login": login})
        except Exception as e:
            self.emit("error", f"GitHub search: {e}", source="GitHub Search")

    # ─── FullContact — free 500/month ─────────────────────────────────────────
    def _fullcontact(self, email):
        key = get_key("FULLCONTACT_KEY")
        if not key:
            return
        try:
            r = requests.post(
                "https://api.fullcontact.com/v3/person.enrich",
                headers={**HEADERS, "Authorization": f"Bearer {key}"},
                json={"email": email},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("fullName"):
                    self.emit("full_name", d["fullName"], source="FullContact")
                if d.get("age"):
                    self.emit("age", str(d["age"]), source="FullContact")
                if d.get("gender"):
                    self.emit("gender", d["gender"], source="FullContact")
                if d.get("location"):
                    self.emit("location", d["location"], source="FullContact")
                if d.get("bio"):
                    self.emit("bio", d["bio"], source="FullContact")
                if d.get("avatar"):
                    self.emit("avatar_url", d["avatar"], source="FullContact")
                if d.get("organization"):
                    self.emit("company", d["organization"], source="FullContact")
                if d.get("title"):
                    self.emit("job_title", d["title"], source="FullContact")
                for social in d.get("socialProfiles", []):
                    url = social.get("url", "")
                    if url:
                        self.emit("social_profile", url, source="FullContact")
        except Exception as e:
            self.emit("error", f"FullContact: {e}", source="FullContact")

    # ─── Clearbit — free 50/month ─────────────────────────────────────────────
    def _clearbit(self, email):
        key = get_key("CLEARBIT_KEY")
        if not key:
            return
        try:
            r = requests.get(
                f"https://person.clearbit.com/v2/combined/find?email={email}",
                auth=(key, ""),
                headers=HEADERS,
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                person  = d.get("person", {})
                company = d.get("company", {})

                if person.get("name", {}).get("fullName"):
                    self.emit("full_name", person["name"]["fullName"], source="Clearbit")
                if person.get("location"):
                    self.emit("location", person["location"], source="Clearbit")
                if person.get("bio"):
                    self.emit("bio", person["bio"], source="Clearbit")
                if person.get("avatar"):
                    self.emit("avatar_url", person["avatar"], source="Clearbit")
                if person.get("site"):
                    self.emit("website", person["site"], source="Clearbit")
                if person.get("employment", {}).get("title"):
                    self.emit("job_title", person["employment"]["title"], source="Clearbit")
                if person.get("employment", {}).get("name"):
                    self.emit("company", person["employment"]["name"], source="Clearbit")

                # Social profiles from Clearbit
                social = person.get("social", {})
                for platform, url in {
                    "twitter":   f"https://twitter.com/{social.get('twitter','')}",
                    "linkedin":  social.get("linkedin", ""),
                    "github":    f"https://github.com/{social.get('github','')}",
                    "facebook":  social.get("facebook", ""),
                }.items():
                    if url and url.rstrip("/") not in ["https://twitter.com/", "https://github.com/"]:
                        self.emit("social_profile", url, source=f"Clearbit ({platform})")

                # Company info
                if company.get("name"):
                    self.emit("company", company["name"], source="Clearbit Company")
                if company.get("domain"):
                    self.emit("company_domain", company["domain"], source="Clearbit Company")
                if company.get("description"):
                    self.emit("company_desc", company["description"][:200], source="Clearbit Company")

            elif r.status_code == 404:
                pass  # No data — silent
            elif r.status_code == 401:
                self.emit("error", "Clearbit: Invalid API key", source="Clearbit")
            elif r.status_code == 402:
                self.emit("error", "Clearbit: Quota exceeded", source="Clearbit")
        except Exception as e:
            self.emit("error", f"Clearbit: {e}", source="Clearbit")