import re
import requests
from duckduckgo_search import DDGS
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# Social / professional domains → emit type
DOMAIN_MAP = {
    "linkedin.com":       "work_profile",
    "github.com":         "github_profile",
    "facebook.com":       "social_profile",
    "instagram.com":      "social_profile",
    "twitter.com":        "social_profile",
    "x.com":              "social_profile",
    "tiktok.com":         "social_profile",
    "youtube.com":        "social_profile",
    "reddit.com":         "social_profile",
    "pinterest.com":      "social_profile",
    "tumblr.com":         "social_profile",
    "medium.com":         "blog_profile",
    "substack.com":       "blog_profile",
    "wordpress.com":      "blog_profile",
    "dev.to":             "blog_profile",
    "twitch.tv":          "social_profile",
    "discord.com":        "social_profile",
    "telegram.me":        "social_profile",
    "t.me":               "social_profile",
    "mastodon.social":    "social_profile",
    "researchgate.net":   "academic_profile",
    "academia.edu":       "academic_profile",
    "scholar.google.com": "academic_profile",
    "orcid.org":          "academic_profile",
    "pacer.gov":          "court_record",
    "courtlistener.com":  "court_record",
    "justia.com":         "court_record",
    "judyrecords.com":    "court_record",
    "publicrecords.com":  "public_record",
    "whitepages.com":     "public_record",
    "spokeo.com":         "public_record",
    "intelius.com":       "public_record",
    "fastpeoplesearch.com": "public_record",
    "truepeoplesearch.com": "public_record",
    "beenverified.com":   "public_record",
    "radaris.com":        "public_record",
    "peekyou.com":        "public_record",
    "pipl.com":           "public_record",
    "zabasearch.com":     "public_record",
    "peoplefinders.com":  "public_record",
    "411.com":            "public_record",
    "addresses.com":      "public_record",
    "usphonebook.com":    "public_record",
    "ussearch.com":       "public_record",
    "checkpeople.com":    "public_record",
    "cyberbackgroundchecks.com": "public_record",
    "newenglandfacts.com": "public_record",
    "familytreenow.com":  "public_record",
    "thatsthem.com":      "public_record",
    "nuwber.com":         "public_record",
    "searchpeoplefree.com": "public_record",
}

# Regex patterns for extracting data from snippets
PATTERNS = {
    "phone":   r'\b(\+?1?\s?[\(\-\.]?\d{3}[\)\-\.\s]\s?\d{3}[\-\.\s]\d{4})\b',
    "email":   r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
    "address": r'\d{1,5}\s[\w\s]{1,30},\s[A-Z]{2}\s\d{5}',
    "age":     r'\bage[d]?\s*:?\s*(\d{2,3})\b|\b(\d{2,3})\s+years?\s+old\b',
}

# Location patterns — pulled from snippets
LOCATION_PATTERNS = [
    r'·\s*([A-Z][a-zA-Z\s]+,\s*[A-Z][a-zA-Z\s]+)\s*(?:·|$)',
    r'(?:based|located|living|lives?|resides?|resident)\s+in\s+([A-Z][a-zA-Z\s]+(?:,\s*[A-Z][a-zA-Z\s]+)?)',
    r'(?:from|originally from|born in|native of)\s+([A-Z][a-zA-Z\s]+(?:,\s*[A-Z][a-zA-Z\s]+)?)',
    r'(?:location|located|address|city|hometown)[:\s]+([A-Z][a-zA-Z\s]+(?:,\s*[A-Z][a-zA-Z\s]+)?)',
    r'\b([A-Z][a-zA-Z\s]+,\s*[A-Z]{2}\s+\d{5})\b',
    r'\bin\s+([A-Z][a-zA-Z\s]+,\s*[A-Z][a-zA-Z\s]+)\b',
]

# World countries/cities for validation
COUNTRIES = {
    "australia","united states","usa","uk","united kingdom","canada","new zealand",
    "india","pakistan","sri lanka","bangladesh","nepal","philippines","indonesia",
    "malaysia","singapore","thailand","vietnam","china","japan","south korea",
    "germany","france","italy","spain","netherlands","sweden","norway","denmark",
    "finland","switzerland","austria","belgium","portugal","poland","russia",
    "brazil","argentina","mexico","colombia","chile","peru","south africa",
    "nigeria","kenya","ghana","egypt","saudi arabia","uae","iran","iraq","turkey",
    "israel","afghanistan","myanmar","cambodia","laos","taiwan","hong kong",
    "new york","london","sydney","melbourne","toronto","vancouver","dubai",
    "paris","berlin","tokyo","beijing","mumbai","delhi","karachi","lahore",
    "colombo","dhaka","kathmandu","manila","jakarta","kuala lumpur","bangkok",
    "ho chi minh","seoul","shanghai","amsterdam","madrid","rome","moscow",
    "sao paulo","buenos aires","cape town","nairobi","auckland","wellington",
    "brisbane","perth","adelaide","christchurch","edinburgh","glasgow","dublin",
}


class ModulePeople(BaseModule):
    name = "people"
    description = "Deep public people discovery — multi-engine search, public records, smart extraction"
    target_types = ["people", "username", "email"]

    def run(self, target, target_type):
        self.results = []
        q = target.strip()

        # Build targeted search queries based on what we're searching
        queries = self._build_queries(q, target_type)

        seen_urls  = set()
        seen_texts = set()

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(self._ddg_search, query, max_r): (query, label)
                       for query, label, max_r in queries}
            for future in as_completed(futures):
                query, label = futures[future]
                try:
                    results = future.result()
                    self._process_results(results, label, seen_urls, seen_texts)
                except Exception as e:
                    self.emit("error", f"{label}: {str(e)}", source="People Search")

        # Hit free public records APIs
        self._free_public_records(q)

        # Wikipedia quick check
        self._wikipedia(q)

        return self.results

    # ─── Query builder ────────────────────────────────────────────────────────
    def _build_queries(self, q, target_type):
        """Return list of (query_string, label, max_results)"""
        words = q.strip().split()
        is_single_word = len(words) == 1

        if target_type == "email":
            return [
                (f'"{q}"', "Email Direct", 15),
                (f'"{q}" site:linkedin.com', "LinkedIn Email", 5),
                (f'"{q}" site:facebook.com', "Facebook Email", 5),
                (f'"{q}" breach leak', "Breach Search", 10),
            ]
        elif target_type == "username":
            return [
                (f'"{q}" site:linkedin.com', "LinkedIn Username", 5),
                (f'"{q}" site:github.com', "GitHub Username", 5),
                (f'"{q}" profile', "Username Profile", 10),
                (f'"{q}" social media', "Username Social", 10),
            ]
        else:
            # Single word → add "person" context to avoid noise
            base = f'"{q}" person' if is_single_word else f'"{q}"'
            return [
                (base, "General", 15),
                (f'"{q}" site:linkedin.com', "LinkedIn", 10),
                (f'"{q}" site:facebook.com', "Facebook", 5),
                (f'"{q}" site:twitter.com OR site:x.com', "Twitter/X", 5),
                (f'"{q}" site:instagram.com', "Instagram", 5),
                (f'"{q}" site:github.com', "GitHub", 5),
                (f'"{q}" location OR city OR country OR "lives in" OR "based in"', "Location Search", 10),
                (f'"{q}" whitepages OR spokeo OR "people search"', "Public Records", 10),
                (f'"{q}" address phone', "Address/Phone", 10),
                (f'"{q}" site:researchgate.net OR site:academia.edu', "Academic", 5),
                (f'"{q}" court records OR arrest OR lawsuit', "Court Records", 5),
            ]

    # ─── DuckDuckGo search ────────────────────────────────────────────────────
    def _ddg_search(self, query, max_results=10):
        with DDGS() as ddgs:
            return list(ddgs.text(query, max_results=max_results))

    # ─── Process & categorise results ─────────────────────────────────────────
    def _process_results(self, results, label, seen_urls, seen_texts):
        for r in results:
            title = r.get("title", "").strip()
            body  = r.get("body", "").strip()
            href  = r.get("href", "").strip()

            # URL categorisation
            if href and href not in seen_urls:
                seen_urls.add(href)
                domain = self._extract_domain(href)
                emit_type = DOMAIN_MAP.get(domain, "profile_url")
                self.emit(emit_type, href, source=label,
                          raw={"title": title, "domain": domain})

            # Title
            if title and title not in seen_texts:
                seen_texts.add(title)
                self.emit("profile_candidate", title, source=label)

            # Body summary + pattern extraction
            combined = f"{title} {body}"
            if body and body not in seen_texts:
                seen_texts.add(body[:100])
                self.emit("profile_summary", body[:300], source=label)

            # Extract structured data from snippets
            self._extract_patterns(combined, label)

    # ─── Pattern extraction ───────────────────────────────────────────────────
    def _extract_patterns(self, text, source):
        for data_type, pattern in PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                val = match if isinstance(match, str) else next((m for m in match if m), None)
                if val:
                    self.emit(data_type, val.strip(), source=f"Extracted ({source})")

        # Location extraction
        self._extract_locations(text, source)

    # ─── Location extraction from text ───────────────────────────────────────
    def _extract_locations(self, text, source):
        seen = set()
        for pattern in LOCATION_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                loc = match.group(1).strip().rstrip(".,·")
                loc = re.sub(r'\s+', ' ', loc)

                if len(loc) < 3 or len(loc) > 60:
                    continue
                if loc.lower() in seen:
                    continue

                # Validate — must contain a known country/city or "City, XX" pattern
                loc_lower = loc.lower()
                is_valid = (
                    any(c in loc_lower for c in COUNTRIES) or
                    re.match(r'^[A-Z][a-zA-Z\s]+,\s*[A-Z]{2}$', loc) or
                    re.match(r'^[A-Z][a-zA-Z\s]+,\s*[A-Z][a-zA-Z\s]+$', loc)
                )

                if is_valid:
                    seen.add(loc.lower())
                    self.emit("location", loc, source=f"Location ({source})")

    # ─── Free public records APIs ─────────────────────────────────────────────
    def _free_public_records(self, name):
        """Hit genuinely free / no-key-needed endpoints"""

        # TruePeopleSearch (no key, scrape-friendly)
        try:
            slug = name.lower().replace(" ", "-")
            r = requests.get(
                f"https://www.truepeoplesearch.com/results?name={requests.utils.quote(name)}",
                headers=HEADERS, timeout=10, allow_redirects=True
            )
            if r.status_code == 200 and name.lower() in r.text.lower():
                self.emit("public_record",
                          f"https://www.truepeoplesearch.com/results?name={requests.utils.quote(name)}",
                          source="TruePeopleSearch")
        except Exception:
            pass

        # FastPeopleSearch
        try:
            r = requests.get(
                f"https://www.fastpeoplesearch.com/name/{requests.utils.quote(name.replace(' ', '-'))}",
                headers=HEADERS, timeout=10, allow_redirects=True
            )
            if r.status_code == 200:
                self.emit("public_record",
                          f"https://www.fastpeoplesearch.com/name/{requests.utils.quote(name.replace(' ', '-'))}",
                          source="FastPeopleSearch")
        except Exception:
            pass

        # FamilyTreeNow (genealogy / public records)
        try:
            r = requests.get(
                f"https://www.familytreenow.com/search/genealogy/results?first={requests.utils.quote(name.split()[0]) if ' ' in name else ''}&last={requests.utils.quote(name.split()[-1])}",
                headers=HEADERS, timeout=10
            )
            if r.status_code == 200 and name.split()[-1].lower() in r.text.lower():
                self.emit("public_record",
                          "https://www.familytreenow.com (result found)",
                          source="FamilyTreeNow")
        except Exception:
            pass

        # Wikidata person lookup
        try:
            r = requests.get(
                "https://www.wikidata.org/w/api.php",
                params={"action": "wbsearchentities", "search": name,
                        "language": "en", "type": "item", "format": "json", "limit": 3},
                headers=HEADERS, timeout=10
            )
            if r.status_code == 200:
                items = r.json().get("search", [])
                for item in items:
                    desc  = item.get("description", "")
                    label = item.get("label", "")
                    qid   = item.get("id", "")
                    if any(kw in desc.lower() for kw in ["person", "politician", "actor", "author",
                                                          "journalist", "athlete", "researcher", "born"]):
                        self.emit("public_figure",
                                  f"{label} — {desc} (Wikidata: {qid})",
                                  source="Wikidata",
                                  raw={"qid": qid, "label": label, "description": desc})
                        self.emit("profile_url",
                                  f"https://www.wikidata.org/wiki/{qid}",
                                  source="Wikidata")

                        # Pull birthplace + location from Wikidata entity
                        try:
                            er = requests.get(
                                "https://www.wikidata.org/w/api.php",
                                params={
                                    "action": "wbgetentities",
                                    "ids": qid,
                                    "props": "claims",
                                    "format": "json",
                                    "languages": "en"
                                },
                                headers=HEADERS, timeout=10
                            )
                            if er.status_code == 200:
                                claims = er.json().get("entities", {}).get(qid, {}).get("claims", {})

                                # P19 = place of birth, P27 = country of citizenship, P551 = residence
                                for prop, label_str in [("P19", "birthplace"), ("P551", "residence"), ("P27", "country")]:
                                    vals = claims.get(prop, [])
                                    for v in vals[:1]:
                                        loc_id = v.get("mainsnak", {}).get("datavalue", {}).get("value", {}).get("id", "")
                                        if loc_id:
                                            # Get label for the location entity
                                            lr = requests.get(
                                                "https://www.wikidata.org/w/api.php",
                                                params={"action": "wbgetentities", "ids": loc_id,
                                                        "props": "labels", "languages": "en", "format": "json"},
                                                headers=HEADERS, timeout=8
                                            )
                                            if lr.status_code == 200:
                                                loc_label = (lr.json()
                                                             .get("entities", {})
                                                             .get(loc_id, {})
                                                             .get("labels", {})
                                                             .get("en", {})
                                                             .get("value", ""))
                                                if loc_label:
                                                    self.emit("location", loc_label,
                                                              source=f"Wikidata ({label_str})",
                                                              raw={"type": label_str, "qid": loc_id})
                        except Exception:
                            pass
        except Exception:
            pass

    # ─── Wikipedia ────────────────────────────────────────────────────────────
    def _wikipedia(self, name):
        try:
            r = requests.get(
                "https://en.wikipedia.org/api/rest_v1/page/summary/" + requests.utils.quote(name.replace(" ", "_")),
                headers=HEADERS, timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                page_type = d.get("type", "")
                extract   = d.get("extract", "")
                page_url  = d.get("content_urls", {}).get("desktop", {}).get("page", "")
                thumbnail = d.get("thumbnail", {}).get("source", "")

                if page_type != "disambiguation" and extract:
                    self.emit("wikipedia_summary", extract[:500], source="Wikipedia")
                    if page_url:
                        self.emit("profile_url", page_url, source="Wikipedia")
                    if thumbnail:
                        self.emit("avatar_url", thumbnail, source="Wikipedia")

                    # Extract locations from Wikipedia summary
                    self._extract_locations(extract, "Wikipedia")

                    # Also check coordinates from Wikipedia API
                    coord = d.get("coordinates", {})
                    if coord and coord.get("lat") and coord.get("lon"):
                        self.emit("coordinates",
                                  f"{coord['lat']}, {coord['lon']}",
                                  source="Wikipedia",
                                  raw=coord)
        except Exception:
            pass

    # ─── Helpers ──────────────────────────────────────────────────────────────
    def _extract_domain(self, url):
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc.lower()
            return host.replace("www.", "")
        except Exception:
            return ""