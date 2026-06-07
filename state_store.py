import json
from pathlib import Path


class StateStore:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self._load()

    def _load(self):
        if not self.path.exists():
            return {"sessions": {}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"sessions": {}}

    def get_last_counter(self, session_id_hex):
        return int(self.data.get("sessions", {}).get(session_id_hex, 0))

    def set_last_counter(self, session_id_hex, counter):
        sessions = self.data.setdefault("sessions", {})
        sessions[session_id_hex] = int(counter)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
