import json
from pathlib import Path


class DeviceRegistry:
    def __init__(self, path):
        self.path = Path(path)
        self.records = self._load()

    def _load(self):
        if not self.path.exists():
            return {"devices": {}}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self):
        self.path.write_text(json.dumps(self.records, indent=2, sort_keys=True), encoding="utf-8")

    def get(self, device_id):
        record = self.records.get("devices", {}).get(device_id)
        if not record:
            raise ValueError(f"Device {device_id!r} is not registered")
        return record

    def upsert(self, public_record):
        devices = self.records.setdefault("devices", {})
        devices[public_record["device_id"]] = public_record
        self.save()
