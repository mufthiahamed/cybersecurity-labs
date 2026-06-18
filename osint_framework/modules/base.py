class BaseModule:
    name = "base"
    description = "Base module"
    target_types = []  # "username", "email", "domain", "ip"

    def __init__(self):
        self.results = []

    def run(self, target, target_type):
        raise NotImplementedError

    def emit(self, data_type, value, source=None, raw=None):
        self.results.append({
            "module": self.name,
            "data_type": data_type,
            "value": value,
            "source": source or "",
            "raw": raw or {}
        })
