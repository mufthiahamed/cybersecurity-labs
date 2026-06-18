import urllib.parse
from .base import BaseModule


class ModuleWeb(BaseModule):
    name = "web"
    description = "Web discovery links for usernames, names, emails and phone-related searches"
    target_types = ["username", "name", "email", "phone"]

    def run(self, target, target_type):
        self.results = []

        q = target.strip()

        searches = [
            ("Google Exact", f'"{q}"'),
            ("Bing Exact", f'"{q}"'),
            ("DuckDuckGo Exact", f'"{q}"'),
            ("Phone Discovery", f'"{q}" phone OR mobile OR contact'),
            ("Email Discovery", f'"{q}" email OR contact'),
            ("Australia Discovery", f'"{q}" Australia'),
            ("LinkedIn Search", f'"{q}" site:linkedin.com/in'),
            ("Facebook Search", f'"{q}" site:facebook.com'),
            ("Instagram Search", f'"{q}" site:instagram.com'),
        ]

        for name, query in searches:
            encoded = urllib.parse.quote(query)

            if name.startswith("Google"):
                url = f"https://www.google.com/search?q={encoded}"
            elif name.startswith("Bing"):
                url = f"https://www.bing.com/search?q={encoded}"
            elif name.startswith("DuckDuckGo"):
                url = f"https://duckduckgo.com/?q={encoded}"
            else:
                url = f"https://www.google.com/search?q={encoded}"

            self.emit("web_search", url, source=name)

        return self.results