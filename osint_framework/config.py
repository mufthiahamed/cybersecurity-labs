"""
Loads API keys from .env file in the project root.
Usage: from config import get_key
       key = get_key("LEAKCHECK_KEY")  # returns "" if not set
"""
import os

_cache = None

def _load():
    global _cache
    if _cache is not None:
        return _cache
    _cache = {}
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                _cache[k.strip()] = v.strip()
    # also honour real environment variables (overrides .env)
    _cache.update({k: v for k, v in os.environ.items() if k in _cache or k.endswith("_KEY")})
    return _cache

def get_key(name, default=""):
    return _load().get(name, default)
