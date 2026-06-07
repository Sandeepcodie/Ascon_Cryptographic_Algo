import hashlib
import json
import secrets
import tempfile
from pathlib import Path

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


ROOM_STORE = Path(tempfile.gettempdir()) / "ascon_room_store.json"
SENDER_ID = "sender_01"
RECEIVER_ID = "receiver_01"


def load_rooms():
    if not ROOM_STORE.exists():
        return {}
    try:
        return json.loads(ROOM_STORE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_rooms(rooms):
    ROOM_STORE.write_text(json.dumps(rooms, indent=2), encoding="utf-8")


def normalize_room(room):
    cleaned = "".join(ch for ch in room.strip().lower() if ch.isalnum() or ch in "-_")
    return cleaned or "secure-room"


def new_device_keys(device_id):
    return DeviceKeys(
        device_id,
        ec.generate_private_key(ec.SECP256R1()),
        ed25519.Ed25519PrivateKey.generate(),
    )


def get_session_keys(role):
    key_name = f"{role}_keys"
    device_id = RECEIVER_ID if role == "receiver" else SENDER_ID
    if key_name not in st.session_state:
        st.session_state[key_name] = new_device_keys(device_id)
    return st.session_state[key_name]


def fingerprint(public_record):
    material = "|".join([
        public_record["device_id"],
        public_record["ecdh_public_key_b64"],
        public_record["signing_public_key_b64"],
    ])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest().upper()
    return ":".join(digest[index:index + 4] for index in range(0, 24, 4))


def get_room(room_id):
    rooms = load_rooms()
    return rooms.get(room_id, {})


def update_room(room_id, values):
    rooms = load_rooms()
    room = rooms.get(room_id, {})
    room.update(values)
    rooms[room_id] = room
    save_rooms(rooms)
    return room


def verify_public_message(message, expected_device_id):
    signing_key = message["signing_public_key_b64"]
    verified = verify_signed_payload(message, signing_key)
    if verified.get("type") != "receiver_public":
        raise ValueError("Wrong public-key message type")
    if verified.get("device_id") != expected_device_id:
        raise ValueError("Wrong receiver identity")
    return {
        "device_id": verified["device_id"],
        "ecdh_public_key_b64": verified["ecdh_public_key_b64"],
        "signing_public_key_b64": verified["signing_public_key_b64"],
    }


def sender_encrypt_for_room(room_id, plaintext):
    sender_keys = get_session_keys("sender")
    room = get_room(room_id)
    receiver_public_message = room.get("receiver_public_message")
    if not receiver_public_message:
        raise ValueError("Receiver has not published a public key in this room")

    receiver_record = verify_public_message(receiver_public_message, RECEIVER_ID)
    session_message, session_id = create_session_message(
        sender_keys,
        receiver_record,
        SENDER_ID,
        RECEIVER_ID,
    )
    ascon_key = derive_sender_key(
        sender_keys,
        receiver_record["ecdh_public_key_b64"],
        session_id,
        SENDER_ID,
        RECEIVER_ID,
    )
    channel = SecureChannel(SENDER_ID, RECEIVER_ID, session_id, ascon_key)
    packet = channel.encrypt(plaintext.encode("utf-8"))

    update_room(room_id, {
        "session_message": session_message,
        "encrypted_packet": packet,
        "sender_public_record": sender_keys.public_record(),
        "sender_fingerprint": fingerprint(sender_keys.public_record()),
        "receiver_fingerprint": fingerprint(receiver_record),
    })

    return {
        "session_id": session_id.hex(),
        "ciphertext_b64": packet["ciphertext_b64"],
        "tag_b64": packet["tag_b64"],
        "receiver_fingerprint": fingerprint(receiver_record),
    }


def receiver_decrypt_from_room(room_id):
    receiver_keys = get_session_keys("receiver")
    room = get_room(room_id)
    session_message = room.get("session_message")
    packet = room.get("encrypted_packet")
    if not session_message or not packet:
        raise ValueError("No encrypted message has arrived in this room")

    signing_key = session_message["sender_signing_public_key_b64"]
    verified = verify_signed_payload(session_message, signing_key)
    if verified.get("type") != "session":
        raise ValueError("Wrong session message type")
    if verified.get("sender_id") != SENDER_ID:
        raise ValueError("Wrong sender identity")
    if verified.get("receiver_id") != RECEIVER_ID:
        raise ValueError("Wrong receiver identity")
    if verified.get("receiver_ecdh_public_key_b64") != receiver_keys.ecdh_public_b64:
        raise ValueError("Session was not created for this receiver public key")

    session_id = bytes.fromhex(verified["session_id"])
    ascon_key = derive_receiver_key(
        receiver_keys,
        verified["sender_ecdh_public_key_b64"],
        session_id,
        SENDER_ID,
        RECEIVER_ID,
    )
    channel = SecureChannel(SENDER_ID, RECEIVER_ID, session_id, ascon_key)
    plaintext = channel.decrypt(packet)

    return {
        "plaintext": plaintext.decode("utf-8"),
        "session_id": verified["session_id"],
        "ciphertext_b64": packet["ciphertext_b64"],
        "tag_b64": packet["tag_b64"],
        "sender_fingerprint": room.get("sender_fingerprint", "unknown"),
    }


st.set_page_config(page_title="ASCON Secure Communication Platform", layout="centered")

st.title("ASCON Secure Communication Platform")
st.caption("Two-user public-key exchange with P-256 ECDH, HKDF-SHA256, Ed25519 signatures, and ASCON authenticated encryption.")

room_id = normalize_room(st.text_input("Room code", value="secure-room-001"))
role = st.radio("Choose your role", ["Receiver", "Sender"], horizontal=True)

st.info("Open this same website in two browser tabs or on two devices. Use the same room code: one user selects Receiver, the other selects Sender.")

if st.button("Clear this room"):
    rooms = load_rooms()
    rooms.pop(room_id, None)
    save_rooms(rooms)
    st.success("Room cleared.")

if role == "Receiver":
    st.subheader("Receiver")
    receiver_keys = get_session_keys("receiver")
    receiver_record = receiver_keys.public_record()
    st.write("Receiver public-key fingerprint")
    st.code(fingerprint(receiver_record))

    if st.button("Publish Receiver Public Key", type="primary"):
        public_message = create_receiver_public_message(receiver_keys)
        update_room(room_id, {
            "receiver_public_message": public_message,
            "receiver_fingerprint": fingerprint(receiver_record),
        })
        st.success("Receiver public key published to the room.")

    st.write("After sender sends a message, click below.")
    if st.button("Check and Decrypt Incoming Message"):
        try:
            result = receiver_decrypt_from_room(room_id)
        except Exception as error:
            st.warning(str(error))
        else:
            st.success("Sender session verified. ASCON tag verified. Message decrypted.")
            st.write("Sender public-key fingerprint")
            st.code(result["sender_fingerprint"])
            st.write("Recovered plaintext")
            st.code(result["plaintext"])
            with st.expander("Encrypted packet details"):
                st.write("Session ID")
                st.code(result["session_id"])
                st.write("Ciphertext")
                st.code(result["ciphertext_b64"])
                st.write("Authentication tag")
                st.code(result["tag_b64"])

else:
    st.subheader("Sender")
    sender_keys = get_session_keys("sender")
    st.write("Sender public-key fingerprint")
    st.code(fingerprint(sender_keys.public_record()))

    room = get_room(room_id)
    receiver_message = room.get("receiver_public_message")
    if receiver_message:
        try:
            receiver_record = verify_public_message(receiver_message, RECEIVER_ID)
        except Exception as error:
            st.error(f"Receiver public key rejected: {error}")
        else:
            st.success("Receiver public key found and signature verified.")
            st.write("Receiver public-key fingerprint")
            st.code(fingerprint(receiver_record))
    else:
        st.warning("Waiting for receiver to publish a public key in this room.")

    message = st.text_area("Message to encrypt", value="Hello from ASCON secure platform")
    if st.button("Encrypt and Send", type="primary"):
        try:
            result = sender_encrypt_for_room(room_id, message)
        except Exception as error:
            st.error(str(error))
        else:
            st.success("Session key derived and encrypted message sent to the room.")
            st.write("Ciphertext sent through the channel")
            st.code(result["ciphertext_b64"])
            with st.expander("Packet details"):
                st.write("Session ID")
                st.code(result["session_id"])
                st.write("Authentication tag")
                st.code(result["tag_b64"])
