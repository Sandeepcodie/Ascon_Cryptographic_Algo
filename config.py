import os
from dataclasses import dataclass
from pathlib import Path


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name, default):
    return int(os.getenv(name, str(default)))


@dataclass(frozen=True)
class Settings:
    role: str
    device_id: str
    peer_id: str
    namespace: str
    mqtt_host: str
    mqtt_port: int
    mqtt_tls: bool
    mqtt_username: str | None
    mqtt_password: str | None
    mqtt_ca_file: str | None
    mqtt_cert_file: str | None
    mqtt_key_file: str | None
    key_dir: Path
    registry_file: Path
    state_file: Path
    plaintext: bytes
    log_session_key: bool

    @property
    def receiver_id(self):
        return self.device_id if self.role == "receiver" else self.peer_id

    @property
    def topic_receiver_public(self):
        return f"{self.namespace}/{self.receiver_id}/receiver_public"

    @property
    def topic_session(self):
        return f"{self.namespace}/{self.receiver_id}/session"

    @property
    def topic_data(self):
        return f"{self.namespace}/{self.receiver_id}/data"


def load_settings(role):
    default_device = "receiver_01" if role == "receiver" else "sender_01"
    default_peer = "sender_01" if role == "receiver" else "receiver_01"
    return Settings(
        role=role,
        device_id=os.getenv("ASCON_DEVICE_ID", default_device),
        peer_id=os.getenv("ASCON_PEER_ID", default_peer),
        namespace=os.getenv("ASCON_PROJECT_NAMESPACE", "ascon_secure_deploy_demo"),
        mqtt_host=os.getenv("ASCON_MQTT_HOST", "localhost"),
        mqtt_port=env_int("ASCON_MQTT_PORT", 8883 if env_bool("ASCON_MQTT_TLS", True) else 1883),
        mqtt_tls=env_bool("ASCON_MQTT_TLS", True),
        mqtt_username=os.getenv("ASCON_MQTT_USERNAME"),
        mqtt_password=os.getenv("ASCON_MQTT_PASSWORD"),
        mqtt_ca_file=os.getenv("ASCON_MQTT_CA_FILE"),
        mqtt_cert_file=os.getenv("ASCON_MQTT_CERT_FILE"),
        mqtt_key_file=os.getenv("ASCON_MQTT_KEY_FILE"),
        key_dir=Path(os.getenv("ASCON_KEY_DIR", "keys")),
        registry_file=Path(os.getenv("ASCON_REGISTRY_FILE", "device_registry.json")),
        state_file=Path(os.getenv("ASCON_STATE_FILE", f"{role}_state.json")),
        plaintext=os.getenv("ASCON_MESSAGE", "YOYO BHai").encode("utf-8"),
        log_session_key=env_bool("ASCON_LOG_SESSION_KEY", False),
    )
