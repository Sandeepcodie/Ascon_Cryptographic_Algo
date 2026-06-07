import copy
import tempfile

from device_keys import load_or_create_device_keys
from registry import DeviceRegistry
from secure_session import (
    SecureChannel,
    create_receiver_public_message,
    create_session_message,
    derive_receiver_key,
    derive_sender_key,
    verify_signed_payload,
)


def build_session():
    with tempfile.TemporaryDirectory() as tmp:
        sender_keys = load_or_create_device_keys("sender_01", tmp)
        receiver_keys = load_or_create_device_keys("receiver_01", tmp)

        registry = DeviceRegistry(f"{tmp}/device_registry.json")
        registry.upsert(sender_keys.public_record())
        registry.upsert(receiver_keys.public_record())

        receiver_public = create_receiver_public_message(receiver_keys)
        verified_receiver = verify_signed_payload(
            receiver_public,
            registry.get("receiver_01")["signing_public_key_b64"],
        )

        session_message, session_id = create_session_message(
            sender_keys,
            registry.get("receiver_01"),
            "sender_01",
            "receiver_01",
        )
        verified_session = verify_signed_payload(
            session_message,
            registry.get("sender_01")["signing_public_key_b64"],
        )

        sender_key = derive_sender_key(
            sender_keys,
            verified_receiver["ecdh_public_key_b64"],
            session_id,
            "sender_01",
            "receiver_01",
        )
        receiver_key = derive_receiver_key(
            receiver_keys,
            verified_session["sender_ecdh_public_key_b64"],
            bytes.fromhex(verified_session["session_id"]),
            "sender_01",
            "receiver_01",
        )

        sender_channel = SecureChannel("sender_01", "receiver_01", session_id, sender_key)
        receiver_channel = SecureChannel("sender_01", "receiver_01", session_id, receiver_key)
        return sender_channel, receiver_channel, session_message, registry.get("sender_01")


def expect_rejected(label, fn):
    try:
        fn()
    except Exception as error:
        print(f"{label}: PASSED - {error}")
        return
    raise RuntimeError(f"{label}: FAILED")


def main():
    sender, receiver, session_message, sender_record = build_session()
    if sender.ascon_key != receiver.ascon_key:
        raise RuntimeError("ECDH/HKDF failed: ASCON keys do not match")
    if len(sender.ascon_key) != 16:
        raise RuntimeError("ASCON key is not 128-bit")

    plaintext = b"YOYO BHai"
    packet = sender.encrypt(plaintext)
    decrypted = receiver.decrypt(packet)
    if decrypted != plaintext:
        raise RuntimeError("Decryption failed")

    print("NORMAL TEST: PASSED")
    print("ECDH -> HKDF -> 128-bit ASCON key: PASSED")

    expect_rejected("REPLAY TEST", lambda: receiver.decrypt(packet))

    fresh_sender, fresh_receiver, _, _ = build_session()
    fresh_packet = fresh_sender.encrypt(plaintext)
    tampered = copy.deepcopy(fresh_packet)
    tampered["ciphertext_b64"] = "A" + tampered["ciphertext_b64"][1:]
    expect_rejected("CIPHERTEXT TAMPER TEST", lambda: fresh_receiver.decrypt(tampered))

    tampered_session = copy.deepcopy(session_message)
    tampered_session["sender_id"] = "attacker"
    expect_rejected(
        "SIGNED SESSION TAMPER TEST",
        lambda: verify_signed_payload(tampered_session, sender_record["signing_public_key_b64"]),
    )


if __name__ == "__main__":
    main()
