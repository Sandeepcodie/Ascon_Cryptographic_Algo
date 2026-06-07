import base64
import json
import secrets
from dataclasses import dataclass
from hmac import compare_digest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ascon_security import ascon_decrypt, ascon_encrypt
from device_keys import b64d, b64e, load_ecdh_public_key, load_signing_public_key


def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hkdf_ascon_key(shared_secret, session_id, first_id, second_id):
    info = b"|".join([
        b"ECDH-P256 HKDF-SHA256 ASCON-128 MQTT DEPLOY",
        session_id,
        first_id.encode("utf-8"),
        second_id.encode("utf-8"),
    ])
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=session_id,
        info=info,
    ).derive(shared_secret)


def make_nonce(session_id, counter):
    return session_id[:8] + int(counter).to_bytes(8, "big")


def make_associated_data(sender_id, receiver_id, session_id, counter):
    return canonical_json({
        "counter": int(counter),
        "receiver_id": receiver_id,
        "sender_id": sender_id,
        "session_id": session_id.hex(),
    })


def sign_payload(device_keys, payload):
    signature = device_keys.sign(canonical_json(payload))
    signed = dict(payload)
    signed["signature_b64"] = b64e(signature)
    return signed


def verify_signed_payload(payload, signing_public_key_b64):
    unsigned = dict(payload)
    signature_b64 = unsigned.pop("signature_b64")
    signing_key = load_signing_public_key(signing_public_key_b64)
    signing_key.verify(b64d(signature_b64), canonical_json(unsigned))
    return unsigned


def create_receiver_public_message(device_keys):
    return sign_payload(device_keys, {
        "type": "receiver_public",
        "device_id": device_keys.device_id,
        "ecdh_public_key_b64": device_keys.ecdh_public_b64,
        "signing_public_key_b64": device_keys.signing_public_b64,
    })


def create_session_message(sender_keys, receiver_public_record, sender_id, receiver_id):
    session_id = secrets.token_bytes(16)
    payload = {
        "type": "session",
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "session_id": session_id.hex(),
        "sender_ecdh_public_key_b64": sender_keys.ecdh_public_b64,
        "sender_signing_public_key_b64": sender_keys.signing_public_b64,
        "receiver_ecdh_public_key_b64": receiver_public_record["ecdh_public_key_b64"],
    }
    return sign_payload(sender_keys, payload), session_id


def derive_sender_key(sender_keys, receiver_ecdh_public_b64, session_id, sender_id, receiver_id):
    receiver_public_key = load_ecdh_public_key(receiver_ecdh_public_b64)
    shared_secret = sender_keys.ecdh_private_key.exchange(ec.ECDH(), receiver_public_key)
    first_id, second_id = sorted([sender_id, receiver_id])
    return hkdf_ascon_key(shared_secret, session_id, first_id, second_id)


def derive_receiver_key(receiver_keys, sender_ecdh_public_b64, session_id, sender_id, receiver_id):
    sender_public_key = load_ecdh_public_key(sender_ecdh_public_b64)
    shared_secret = receiver_keys.ecdh_private_key.exchange(ec.ECDH(), sender_public_key)
    first_id, second_id = sorted([sender_id, receiver_id])
    return hkdf_ascon_key(shared_secret, session_id, first_id, second_id)


@dataclass
class SecureChannel:
    sender_id: str
    receiver_id: str
    session_id: bytes
    ascon_key: bytes
    send_counter: int = 0
    last_received_counter: int = 0

    def encrypt(self, plaintext):
        self.send_counter += 1
        counter = self.send_counter
        nonce = make_nonce(self.session_id, counter)
        ad = make_associated_data(self.sender_id, self.receiver_id, self.session_id, counter)
        combined = ascon_encrypt(self.ascon_key, nonce, ad, plaintext)
        return {
            "type": "data",
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "session_id": self.session_id.hex(),
            "counter": counter,
            "nonce_b64": b64e(nonce),
            "associated_data_b64": b64e(ad),
            "ciphertext_b64": b64e(combined[:-16]),
            "tag_b64": b64e(combined[-16:]),
        }

    def decrypt(self, packet):
        if packet.get("sender_id") != self.sender_id:
            raise ValueError("Wrong sender id")
        if packet.get("receiver_id") != self.receiver_id:
            raise ValueError("Wrong receiver id")
        if packet.get("session_id") != self.session_id.hex():
            raise ValueError("Wrong session id")

        counter = int(packet["counter"])
        if counter <= self.last_received_counter:
            raise ValueError("Replay attack rejected")

        nonce = b64d(packet["nonce_b64"])
        expected_nonce = make_nonce(self.session_id, counter)
        if not compare_digest(nonce, expected_nonce):
            raise ValueError("Wrong nonce")

        ad = b64d(packet["associated_data_b64"])
        expected_ad = make_associated_data(self.sender_id, self.receiver_id, self.session_id, counter)
        if not compare_digest(ad, expected_ad):
            raise ValueError("Wrong associated data")

        combined = b64d(packet["ciphertext_b64"]) + b64d(packet["tag_b64"])
        plaintext = ascon_decrypt(self.ascon_key, nonce, ad, combined)
        self.last_received_counter = counter
        return plaintext
