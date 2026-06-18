import requests
from .base import BaseModule

class ModuleReddit(BaseModule):
    name = "reddit"
    description = "Query Reddit public API for user activity and post history"
    target_types = ["username"]

    def run(self, target, target_type):
        self.results = []
        username = target.strip().lstrip("@")

        try:
            r = requests.get(
                f"https://www.reddit.com/user/{username}/about.json",
                headers={"User-Agent": "osint-framework/1.0"},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                self.emit("profile_url", f"https://reddit.com/u/{username}", source="Reddit API")
                self.emit("stat", f"Karma: {d.get('total_karma', 0):,}", source="Reddit API")
                self.emit("account_created", str(d.get("created_utc", ""))[:10], source="Reddit API")
                if d.get("verified"):
                    self.emit("verified_email", "Email verified on Reddit", source="Reddit API")
                if d.get("is_gold"):
                    self.emit("account_detail", "Reddit Premium member", source="Reddit API")
            elif r.status_code == 404:
                self.emit("not_found", f"No Reddit account for u/{username}", source="Reddit API")
                return self.results
        except Exception as e:
            self.emit("error", str(e), source="Reddit API")
            return self.results

        # recent comments
        try:
            r = requests.get(
                f"https://www.reddit.com/user/{username}/comments/.json?limit=5",
                headers={"User-Agent": "osint-framework/1.0"},
                timeout=10
            )
            if r.status_code == 200:
                items = r.json().get("data", {}).get("children", [])
                subreddits = set()
                for item in items:
                    d = item.get("data", {})
                    subreddits.add(d.get("subreddit", ""))
                    self.emit("post_snippet", d.get("body", "")[:200], source="Reddit Comments",
                              raw={"subreddit": d.get("subreddit"), "score": d.get("score", 0),
                                   "url": f"https://reddit.com{d.get('permalink','')}"})
                for sub in subreddits:
                    if sub:
                        self.emit("subreddit_activity", f"r/{sub}", source="Reddit API")
        except Exception as e:
            self.emit("error", str(e), source="Reddit Comments")

        # recent submissions
        try:
            r = requests.get(
                f"https://www.reddit.com/user/{username}/submitted/.json?limit=5",
                headers={"User-Agent": "osint-framework/1.0"},
                timeout=10
            )
            if r.status_code == 200:
                for item in r.json().get("data", {}).get("children", []):
                    d = item.get("data", {})
                    self.emit("post_title", d.get("title", "")[:150], source="Reddit Submissions",
                              raw={"subreddit": d.get("subreddit"), "score": d.get("score", 0),
                                   "url": f"https://reddit.com{d.get('permalink','')}"})
        except Exception as e:
            self.emit("error", str(e), source="Reddit Submissions")

        return self.results
