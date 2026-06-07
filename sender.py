import json
import time

from config import load_settings
from device_keys import load_or_create_device_keys
from mqtt_client import get_mqtt_module, make_client
from registry import DeviceRegistry
from secure_session import (
    SecureChannel,
    create_session_message,
    derive_sender_key,
    verify_signed_payload,
)


def main():
    settings = load_settings("sender")
    keys = load_or_create_device_keys(settings.device_id, settings.key_dir)
    registry = DeviceRegistry(settings.registry_file)
    peer_record = registry.get(settings.peer_id)
    mqtt = get_mqtt_module()
    sent = False

    print("========== ASCON SECURE SENDER ==========")
    print(f"Device      : {settings.device_id}")
    print(f"Peer        : {settings.peer_id}")
    print(f"Broker      : {settings.mqtt_host}:{settings.mqtt_port}")
    print(f"TLS enabled : {settings.mqtt_tls}")
    print(f"Namespace   : {settings.namespace}")
    print()

    def on_connect(client, userdata, flags, reason_code, properties=None):
        if reason_code != 0:
            print(f"MQTT connection failed: {reason_code}")
            return
        client.subscribe(settings.topic_receiver_public, qos=1)
        print("Waiting for signed receiver public-key message...")

    def on_message(client, userdata, msg):
        nonlocal sent
        if sent:
            return

        try:
            payload = json.loads(msg.payload.decode("utf-8").strip())
            verified = verify_signed_payload(payload, peer_record["signing_public_key_b64"])
            if verified.get("type") != "receiver_public":
                raise ValueError("Wrong message type")
            if verified.get("device_id") != settings.peer_id:
                raise ValueError("Wrong receiver id")
            if verified.get("ecdh_public_key_b64") != peer_record["ecdh_public_key_b64"]:
                raise ValueError("Receiver ECDH key is not registered")
            if verified.get("signing_public_key_b64") != peer_record["signing_public_key_b64"]:
                raise ValueError("Receiver signing key is not registered")

            session_message, session_id = create_session_message(
                keys,
                peer_record,
                settings.device_id,
                settings.peer_id,
            )
            ascon_key = derive_sender_key(
                keys,
                peer_record["ecdh_public_key_b64"],
                session_id,
                settings.device_id,
                settings.peer_id,
            )
            channel = SecureChannel(settings.device_id, settings.peer_id, session_id, ascon_key)
            packet = channel.encrypt(settings.plaintext)

            client.publish(settings.topic_session, json.dumps(session_message), qos=1)
            time.sleep(0.3)
            client.publish(settings.topic_data, json.dumps(packet), qos=1)
            sent = True

            print("Receiver identity verified.")
            print("Signed session message sent.")
            print("Encrypted packet sent.")
            if settings.log_session_key:
                print(f"ASCON key: {ascon_key.hex()}")
            print(f"Plaintext: {settings.plaintext}")
            print(f"Ciphertext b64: {packet['ciphertext_b64']}")
            client.disconnect()

        except Exception as error:
            print(f"Sender error: {error}")
            client.disconnect()

    client = make_client(mqtt, settings)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    main()
