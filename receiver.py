import json

from config import load_settings
from device_keys import load_or_create_device_keys
from mqtt_client import get_mqtt_module, make_client
from registry import DeviceRegistry
from secure_session import (
    SecureChannel,
    create_receiver_public_message,
    derive_receiver_key,
    verify_signed_payload,
)
from state_store import StateStore


def main():
    settings = load_settings("receiver")
    keys = load_or_create_device_keys(settings.device_id, settings.key_dir)
    registry = DeviceRegistry(settings.registry_file)
    peer_record = registry.get(settings.peer_id)
    state = StateStore(settings.state_file)
    mqtt = get_mqtt_module()
    channel = None

    print("========== ASCON SECURE RECEIVER ==========")
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

        client.subscribe(settings.topic_session, qos=1)
        client.subscribe(settings.topic_data, qos=1)
        client.publish(
            settings.topic_receiver_public,
            json.dumps(create_receiver_public_message(keys)),
            qos=1,
            retain=True,
        )
        print("Signed receiver public-key message published.")
        print("Waiting for signed session message...")

    def on_message(client, userdata, msg):
        nonlocal channel
        try:
            payload = json.loads(msg.payload.decode("utf-8"))

            if msg.topic == settings.topic_session:
                verified = verify_signed_payload(payload, peer_record["signing_public_key_b64"])
                if verified.get("type") != "session":
                    raise ValueError("Wrong message type")
                if verified.get("sender_id") != settings.peer_id:
                    raise ValueError("Wrong sender id")
                if verified.get("receiver_id") != settings.device_id:
                    raise ValueError("Wrong receiver id")
                if verified.get("sender_ecdh_public_key_b64") != peer_record["ecdh_public_key_b64"]:
                    raise ValueError("Sender ECDH key is not registered")
                if verified.get("sender_signing_public_key_b64") != peer_record["signing_public_key_b64"]:
                    raise ValueError("Sender signing key is not registered")
                if verified.get("receiver_ecdh_public_key_b64") != keys.ecdh_public_b64:
                    raise ValueError("Session was not addressed to this receiver key")

                session_id = bytes.fromhex(verified["session_id"])
                ascon_key = derive_receiver_key(
                    keys,
                    verified["sender_ecdh_public_key_b64"],
                    session_id,
                    settings.peer_id,
                    settings.device_id,
                )
                channel = SecureChannel(settings.peer_id, settings.device_id, session_id, ascon_key)
                channel.last_received_counter = state.get_last_counter(verified["session_id"])
                print("Signed session verified and ASCON session key derived.")
                if settings.log_session_key:
                    print(f"ASCON key: {ascon_key.hex()}")

            elif msg.topic == settings.topic_data:
                if channel is None:
                    raise ValueError("No verified session yet")
                plaintext = channel.decrypt(payload)
                state.set_last_counter(payload["session_id"], payload["counter"])
                print("Encrypted packet verified.")
                print(f"Decrypted: {plaintext}")

        except Exception as error:
            print(f"Rejected message: {error}")

    client = make_client(mqtt, settings)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=60)

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\nReceiver stopped.")
        client.publish(settings.topic_receiver_public, "", qos=1, retain=True)
        client.disconnect()


if __name__ == "__main__":
    main()
