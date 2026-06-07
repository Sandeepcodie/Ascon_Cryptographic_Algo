from config import load_settings
from device_keys import load_or_create_device_keys
from registry import DeviceRegistry


def main():
    settings = load_settings("sender")
    registry = DeviceRegistry(settings.registry_file)

    for device_id in [settings.device_id, settings.peer_id]:
        keys = load_or_create_device_keys(device_id, settings.key_dir)
        registry.upsert(keys.public_record())
        print(f"Registered {device_id}")
        print(f"  ECDH public   : {keys.ecdh_public_b64}")
        print(f"  Ed25519 public: {keys.signing_public_b64}")

    print()
    print(f"Registry written: {settings.registry_file}")
    print(f"Private keys in : {settings.key_dir}")


if __name__ == "__main__":
    main()
