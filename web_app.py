import secrets

import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from device_keys import DeviceKeys
from secure_session import (
    SecureChannel,
    create_receiver_public_message,
    create_session_message,
    derive_receiver_key,
    derive_sender_key,
    verify_signed_payload,
)


SENDER_ID = "sender_01"
RECEIVER_ID = "receiver_01"


def prepare_demo_devices():
    sender_keys = DeviceKeys(
        SENDER_ID,
        ec.generate_private_key(ec.SECP256R1()),
        ed25519.Ed25519PrivateKey.generate(),
    )
    receiver_keys = DeviceKeys(
        RECEIVER_ID,
        ec.generate_private_key(ec.SECP256R1()),
        ed25519.Ed25519PrivateKey.generate(),
    )

    registry = {
        SENDER_ID: sender_keys.public_record(),
        RECEIVER_ID: receiver_keys.public_record(),
    }

    return sender_keys, receiver_keys, registry


def run_secure_demo(message):
    sender_keys, receiver_keys, registry = prepare_demo_devices()
    sender_record = registry[SENDER_ID]
    receiver_record = registry[RECEIVER_ID]

    receiver_public_message = create_receiver_public_message(receiver_keys)
    verified_receiver = verify_signed_payload(
        receiver_public_message,
        receiver_record["signing_public_key_b64"],
    )

    if verified_receiver["device_id"] != RECEIVER_ID:
        raise ValueError("Receiver identity verification failed")

    session_message, session_id = create_session_message(
        sender_keys,
        receiver_record,
        SENDER_ID,
        RECEIVER_ID,
    )
    verified_session = verify_signed_payload(
        session_message,
        sender_record["signing_public_key_b64"],
    )

    if verified_session["sender_id"] != SENDER_ID:
        raise ValueError("Sender identity verification failed")
    if verified_session["receiver_id"] != RECEIVER_ID:
        raise ValueError("Receiver id mismatch in session")

    sender_key = derive_sender_key(
        sender_keys,
        receiver_record["ecdh_public_key_b64"],
        session_id,
        SENDER_ID,
        RECEIVER_ID,
    )
    receiver_key = derive_receiver_key(
        receiver_keys,
        sender_record["ecdh_public_key_b64"],
        session_id,
        SENDER_ID,
        RECEIVER_ID,
    )

    if not secrets.compare_digest(sender_key, receiver_key):
        raise ValueError("ECDH/HKDF key agreement failed")

    sender_channel = SecureChannel(SENDER_ID, RECEIVER_ID, session_id, sender_key)
    receiver_channel = SecureChannel(SENDER_ID, RECEIVER_ID, session_id, receiver_key)

    packet = sender_channel.encrypt(message.encode("utf-8"))
    decrypted = receiver_channel.decrypt(packet)

    return {
        "session_id": session_id.hex(),
        "ascon_key_hex": sender_key.hex(),
        "ciphertext_b64": packet["ciphertext_b64"],
        "tag_b64": packet["tag_b64"],
        "decrypted": decrypted.decode("utf-8"),
    }


st.set_page_config(page_title="ASCON Secure Communication", layout="centered")

st.title("ASCON Secure Communication")
st.caption("P-256 ECDH + HKDF-SHA256 + 128-bit ASCON authenticated encryption")

st.subheader("Sender")
message = st.text_input("Plaintext message", value="Hello from ASCON secure web deployment")

if st.button("Encrypt and Send", type="primary"):
    try:
        result = run_secure_demo(message)
    except Exception as error:
        st.error(f"Secure communication failed: {error}")
    else:
        st.success("Message encrypted, authenticated, verified, and decrypted by the receiver.")

        st.subheader("Encrypted MQTT Packet")
        st.write("Only ciphertext and authentication data are sent through the communication channel.")
        st.write("**Ciphertext**")
        st.code(result["ciphertext_b64"])
        st.write("**Authentication tag**")
        st.code(result["tag_b64"])

        st.subheader("Receiver")
        st.write("The receiver verifies the session, nonce, associated data, replay counter, and ASCON tag before decryption.")
        st.write("**Recovered plaintext**")
        st.code(result["decrypted"])

        with st.expander("Technical details"):
            st.write("Security flow: P-256 ECDH -> HKDF-SHA256 -> 128-bit ASCON key -> authenticated encryption")
            st.write("**Session ID**")
            st.code(result["session_id"])
            st.write("**Demo ASCON session key**")
            st.code(result["ascon_key_hex"])
