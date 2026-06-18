import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule

# 100+ platforms — errorType: "status_code" | "message" | "response_url"
PLATFORMS = [
    # === SOCIAL MEDIA ===
    {"name": "Twitter/X",       "url": "https://x.com/{}",                              "errorType": "status_code"},
    {"name": "Instagram",       "url": "https://www.instagram.com/{}/",                 "errorType": "status_code"},
    {"name": "TikTok",          "url": "https://www.tiktok.com/@{}",                    "errorType": "status_code"},
    {"name": "Facebook",        "url": "https://www.facebook.com/{}",                   "errorType": "status_code"},
    {"name": "Pinterest",       "url": "https://www.pinterest.com/{}/",                 "errorType": "status_code"},
    {"name": "Snapchat",        "url": "https://www.snapchat.com/add/{}",               "errorType": "status_code"},
    {"name": "Tumblr",          "url": "https://{}.tumblr.com/",                        "errorType": "status_code"},
    {"name": "Flickr",          "url": "https://www.flickr.com/people/{}",              "errorType": "status_code"},
    {"name": "VK",              "url": "https://vk.com/{}",                             "errorType": "status_code"},
    {"name": "OK.ru",           "url": "https://ok.ru/{}",                              "errorType": "status_code"},
    {"name": "Mastodon",        "url": "https://mastodon.social/@{}",                   "errorType": "status_code"},
    {"name": "Threads",         "url": "https://www.threads.net/@{}",                   "errorType": "status_code"},
    {"name": "Bluesky",         "url": "https://bsky.app/profile/{}.bsky.social",       "errorType": "status_code"},
    {"name": "Minds",           "url": "https://www.minds.com/{}",                      "errorType": "status_code"},
    {"name": "MeWe",            "url": "https://mewe.com/i/{}",                         "errorType": "status_code"},
    {"name": "Diaspora",        "url": "https://diaspora.social/u/{}",                  "errorType": "status_code"},
    {"name": "Gab",             "url": "https://gab.com/{}",                            "errorType": "status_code"},
    {"name": "Parler",          "url": "https://parler.com/{}",                         "errorType": "status_code"},

    # === PROFESSIONAL / DEVELOPER ===
    {"name": "LinkedIn",        "url": "https://www.linkedin.com/in/{}/",               "errorType": "status_code"},
    {"name": "GitHub",          "url": "https://github.com/{}",                         "errorType": "status_code"},
    {"name": "GitLab",          "url": "https://gitlab.com/{}",                         "errorType": "status_code"},
    {"name": "Bitbucket",       "url": "https://bitbucket.org/{}",                      "errorType": "status_code"},
    {"name": "SourceForge",     "url": "https://sourceforge.net/u/{}/profile/",         "errorType": "status_code"},
    {"name": "Codeberg",        "url": "https://codeberg.org/{}",                       "errorType": "status_code"},
    {"name": "Gitea",           "url": "https://gitea.com/{}",                          "errorType": "status_code"},
    {"name": "Dev.to",          "url": "https://dev.to/{}",                             "errorType": "status_code"},
    {"name": "Medium",          "url": "https://medium.com/@{}",                        "errorType": "status_code"},
    {"name": "Hashnode",        "url": "https://hashnode.com/@{}",                      "errorType": "status_code"},
    {"name": "HackerNews",      "url": "https://hacker-news.firebaseio.com/v0/user/{}.json", "errorType": "message", "errorMsg": "null"},
    {"name": "Stack Overflow",  "url": "https://stackoverflow.com/users/{}",            "errorType": "status_code"},
    {"name": "Stack Exchange",  "url": "https://stackexchange.com/users/{}",            "errorType": "status_code"},
    {"name": "Replit",          "url": "https://replit.com/@{}",                        "errorType": "status_code"},
    {"name": "Glitch",          "url": "https://glitch.com/@{}",                        "errorType": "status_code"},
    {"name": "CodePen",         "url": "https://codepen.io/{}",                         "errorType": "status_code"},
    {"name": "JSFiddle",        "url": "https://jsfiddle.net/user/{}/",                 "errorType": "status_code"},
    {"name": "npm",             "url": "https://www.npmjs.com/~{}",                     "errorType": "status_code"},
    {"name": "PyPI",            "url": "https://pypi.org/user/{}/",                     "errorType": "status_code"},
    {"name": "crates.io",       "url": "https://crates.io/users/{}",                    "errorType": "status_code"},
    {"name": "RubyGems",        "url": "https://rubygems.org/profiles/{}",              "errorType": "status_code"},
    {"name": "Packagist",       "url": "https://packagist.org/packages/{}/",            "errorType": "status_code"},
    {"name": "DockerHub",       "url": "https://hub.docker.com/u/{}",                   "errorType": "status_code"},
    {"name": "Kaggle",          "url": "https://www.kaggle.com/{}",                     "errorType": "status_code"},
    {"name": "Hugging Face",    "url": "https://huggingface.co/{}",                     "errorType": "status_code"},
    {"name": "LeetCode",        "url": "https://leetcode.com/{}",                       "errorType": "status_code"},
    {"name": "HackerRank",      "url": "https://www.hackerrank.com/{}",                 "errorType": "status_code"},
    {"name": "Codeforces",      "url": "https://codeforces.com/profile/{}",             "errorType": "status_code"},
    {"name": "TopCoder",        "url": "https://www.topcoder.com/members/{}",           "errorType": "status_code"},
    {"name": "AtCoder",         "url": "https://atcoder.jp/users/{}",                   "errorType": "status_code"},

    # === CONTENT / CREATIVE ===
    {"name": "YouTube",         "url": "https://www.youtube.com/@{}",                   "errorType": "status_code"},
    {"name": "Twitch",          "url": "https://www.twitch.tv/{}",                      "errorType": "status_code"},
    {"name": "Kick",            "url": "https://kick.com/{}",                           "errorType": "status_code"},
    {"name": "Rumble",          "url": "https://rumble.com/c/{}",                       "errorType": "status_code"},
    {"name": "Dailymotion",     "url": "https://www.dailymotion.com/{}",                "errorType": "status_code"},
    {"name": "Vimeo",           "url": "https://vimeo.com/{}",                          "errorType": "status_code"},
    {"name": "SoundCloud",      "url": "https://soundcloud.com/{}",                     "errorType": "status_code"},
    {"name": "Spotify",         "url": "https://open.spotify.com/user/{}",              "errorType": "status_code"},
    {"name": "Last.fm",         "url": "https://www.last.fm/user/{}",                   "errorType": "status_code"},
    {"name": "Bandcamp",        "url": "https://{}.bandcamp.com/",                      "errorType": "status_code"},
    {"name": "Mixcloud",        "url": "https://www.mixcloud.com/{}/",                  "errorType": "status_code"},
    {"name": "Audiomack",       "url": "https://audiomack.com/{}",                      "errorType": "status_code"},
    {"name": "Patreon",         "url": "https://www.patreon.com/{}",                    "errorType": "status_code"},
    {"name": "Ko-fi",           "url": "https://ko-fi.com/{}",                          "errorType": "status_code"},
    {"name": "Buy Me a Coffee", "url": "https://www.buymeacoffee.com/{}",               "errorType": "status_code"},
    {"name": "OnlyFans",        "url": "https://onlyfans.com/{}",                       "errorType": "status_code"},
    {"name": "Substack",        "url": "https://{}.substack.com/",                      "errorType": "status_code"},
    {"name": "Ghost",           "url": "https://{}.ghost.io/",                          "errorType": "status_code"},
    {"name": "WordPress",       "url": "https://{}.wordpress.com/",                     "errorType": "status_code"},
    {"name": "Wattpad",         "url": "https://www.wattpad.com/user/{}",               "errorType": "status_code"},
    {"name": "Archive of Our Own","url": "https://archiveofourown.org/users/{}",        "errorType": "status_code"},
    {"name": "DeviantArt",      "url": "https://www.deviantart.com/{}",                 "errorType": "status_code"},
    {"name": "ArtStation",      "url": "https://www.artstation.com/{}",                 "errorType": "status_code"},
    {"name": "Behance",         "url": "https://www.behance.net/{}",                    "errorType": "status_code"},
    {"name": "Dribbble",        "url": "https://dribbble.com/{}",                       "errorType": "status_code"},
    {"name": "500px",           "url": "https://500px.com/p/{}",                        "errorType": "status_code"},
    {"name": "Unsplash",        "url": "https://unsplash.com/@{}",                      "errorType": "status_code"},

    # === FORUMS / COMMUNITY ===
    {"name": "Reddit",          "url": "https://www.reddit.com/user/{}/about.json",     "errorType": "message", "errorMsg": "\"error\": 404"},
    {"name": "Quora",           "url": "https://www.quora.com/profile/{}",              "errorType": "status_code"},
    {"name": "Disqus",          "url": "https://disqus.com/{}",                         "errorType": "status_code"},
    {"name": "ProductHunt",     "url": "https://www.producthunt.com/@{}",               "errorType": "status_code"},
    {"name": "Indie Hackers",   "url": "https://www.indiehackers.com/{}",               "errorType": "status_code"},
    {"name": "Lobste.rs",       "url": "https://lobste.rs/u/{}",                        "errorType": "status_code"},
    {"name": "4chan",            "url": "https://boards.4chan.org/{}",                   "errorType": "status_code"},
    {"name": "Kbin",            "url": "https://kbin.social/u/{}",                      "errorType": "status_code"},
    {"name": "Lemmy",           "url": "https://lemmy.world/u/{}",                      "errorType": "status_code"},

    # === GAMING ===
    {"name": "Steam",           "url": "https://steamcommunity.com/id/{}",              "errorType": "message", "errorMsg": "The specified profile could not be found"},
    {"name": "Xbox",            "url": "https://xboxgamertag.com/search/{}",            "errorType": "status_code"},
    {"name": "PSN",             "url": "https://psnprofiles.com/{}",                    "errorType": "status_code"},
    {"name": "Twitch",          "url": "https://www.twitch.tv/{}",                      "errorType": "status_code"},
    {"name": "Roblox",          "url": "https://www.roblox.com/user.aspx?username={}",  "errorType": "status_code"},
    {"name": "Minecraft",       "url": "https://namemc.com/profile/{}",                 "errorType": "status_code"},
    {"name": "Chess.com",       "url": "https://www.chess.com/member/{}",               "errorType": "status_code"},
    {"name": "Lichess",         "url": "https://lichess.org/@/{}",                      "errorType": "status_code"},
    {"name": "Itch.io",         "url": "https://{}.itch.io/",                           "errorType": "status_code"},
    {"name": "GameJolt",        "url": "https://gamejolt.com/@{}",                      "errorType": "status_code"},

    # === IDENTITY / UTILITY ===
    {"name": "Gravatar",        "url": "https://en.gravatar.com/{}",                    "errorType": "status_code"},
    {"name": "Keybase",         "url": "https://keybase.io/{}",                         "errorType": "status_code"},
    {"name": "About.me",        "url": "https://about.me/{}",                           "errorType": "status_code"},
    {"name": "Linktree",        "url": "https://linktr.ee/{}",                          "errorType": "status_code"},
    {"name": "Carrd",           "url": "https://{}.carrd.co/",                          "errorType": "status_code"},
    {"name": "Bento",           "url": "https://bento.me/{}",                           "errorType": "status_code"},
    {"name": "Contra",          "url": "https://contra.com/{}",                         "errorType": "status_code"},
    {"name": "Pastebin",        "url": "https://pastebin.com/u/{}",                     "errorType": "status_code"},
    {"name": "Trello",          "url": "https://trello.com/{}",                         "errorType": "status_code"},
    {"name": "Notion",          "url": "https://notion.so/{}",                          "errorType": "status_code"},

    # === Q&A / KNOWLEDGE ===
    {"name": "Academia.edu",    "url": "https://independent.academia.edu/{}",           "errorType": "status_code"},
    {"name": "ResearchGate",    "url": "https://www.researchgate.net/profile/{}",       "errorType": "status_code"},
    {"name": "Goodreads",       "url": "https://www.goodreads.com/{}",                  "errorType": "status_code"},

    # === REGIONAL ===
    {"name": "Weibo",           "url": "https://weibo.com/{}",                          "errorType": "status_code"},
    {"name": "Bilibili",        "url": "https://space.bilibili.com/{}",                 "errorType": "status_code"},
    {"name": "Naver",           "url": "https://blog.naver.com/{}",                     "errorType": "status_code"},
    {"name": "Taringa",         "url": "https://www.taringa.net/{}",                    "errorType": "status_code"},

    # === MISC ===
    {"name": "Letterboxd",      "url": "https://letterboxd.com/{}",                     "errorType": "status_code"},
    {"name": "Strava",          "url": "https://www.strava.com/athletes/{}",            "errorType": "status_code"},
    {"name": "Duolingo",        "url": "https://www.duolingo.com/profile/{}",           "errorType": "status_code"},
    {"name": "Fiverr",          "url": "https://www.fiverr.com/{}",                     "errorType": "status_code"},
    {"name": "Upwork",          "url": "https://www.upwork.com/freelancers/~{}",        "errorType": "status_code"},
    {"name": "Freelancer",      "url": "https://www.freelancer.com/u/{}",               "errorType": "status_code"},
    {"name": "AngelList",       "url": "https://angel.co/u/{}",                         "errorType": "status_code"},
    {"name": "Crunchbase",      "url": "https://www.crunchbase.com/person/{}",          "errorType": "status_code"},
    {"name": "Wikipedia",       "url": "https://en.wikipedia.org/wiki/User:{}",         "errorType": "status_code"},
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Deduplicate by name
_seen = set()
_deduped = []
for p in PLATFORMS:
    if p["name"] not in _seen:
        _seen.add(p["name"])
        _deduped.append(p)
PLATFORMS = _deduped


class ModuleSocial(BaseModule):
    name = "social"
    description = f"Check username across {len(PLATFORMS)} social platforms"
    target_types = ["username"]

    def _check(self, platform, username):
        url = platform["url"].format(username)
        error_type = platform.get("errorType", "status_code")
        error_msg = platform.get("errorMsg", "")

        try:
            r = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)

            if error_type == "status_code":
                found = r.status_code not in [404, 410, 400, 403]
            elif error_type == "message":
                found = error_msg not in r.text and r.status_code not in [404, 410]
            elif error_type == "response_url":
                found = error_msg not in r.url
            else:
                found = r.status_code == 200

            return {
                "name": platform["name"],
                "url": url,
                "found": found,
                "status": r.status_code
            }
        except requests.exceptions.Timeout:
            return {"name": platform["name"], "url": url, "found": False, "status": 0, "error": "timeout"}
        except requests.exceptions.ConnectionError:
            return {"name": platform["name"], "url": url, "found": False, "status": 0, "error": "connection_error"}
        except Exception as e:
            return {"name": platform["name"], "url": url, "found": False, "status": 0, "error": str(e)}

    def run(self, target, target_type):
        self.results = []
        username = target.strip().lstrip("@")

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(self._check, p, username): p for p in PLATFORMS}
            for future in as_completed(futures):
                result = future.result()
                if result["found"]:
                    self.emit(
                        "social_profile",
                        result["url"],
                        source=f"Username Check ({result['name']})",
                        raw={
                            "platform": result["name"],
                            "status": result["status"]
                        }
                    )
                else:
                    self.emit(
                        "not_found",
                        f"{result['name']}: not found",
                        source="Username Check",
                        raw={
                            "platform": result["name"],
                            "error": result.get("error", "")
                        }
                    )

        return self.results