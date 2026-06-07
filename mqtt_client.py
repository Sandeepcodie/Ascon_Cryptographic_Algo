import secrets
import ssl


def get_mqtt_module():
    try:
        import paho.mqtt.client as mqtt
    except ModuleNotFoundError:
        print("paho-mqtt is missing. Install it with: pip install -r requirements.txt")
        raise SystemExit(1)
    return mqtt


def make_client(mqtt, settings):
    client_id = f"ascon-{settings.role}-{settings.device_id}-{secrets.token_hex(4)}"
    if hasattr(mqtt, "CallbackAPIVersion"):
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    else:
        client = mqtt.Client(client_id=client_id)

    if settings.mqtt_username:
        client.username_pw_set(settings.mqtt_username, settings.mqtt_password)

    if settings.mqtt_tls:
        client.tls_set(
            ca_certs=settings.mqtt_ca_file,
            certfile=settings.mqtt_cert_file,
            keyfile=settings.mqtt_key_file,
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS_CLIENT,
        )
        client.tls_insecure_set(False)

    return client
