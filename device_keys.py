import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


def b64e(data):
    return base64.b64encode(data).decode("ascii")


def b64d(data):
    return base64.b64decode(data.encode("ascii"))


class DeviceKeys:
    def __init__(self, device_id, ecdh_private_key, signing_private_key):
        self.device_id = device_id
        self.ecdh_private_key = ecdh_private_key
        self.signing_private_key = signing_private_key

    @property
    def ecdh_public_b64(self):
        data = self.ecdh_private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        return b64e(data)

    @property
    def signing_public_b64(self):
        data = self.signing_private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return b64e(data)

    def sign(self, data):
        return self.signing_private_key.sign(data)

    def public_record(self):
        return {
            "device_id": self.device_id,
            "ecdh_public_key_b64": self.ecdh_public_b64,
            "signing_public_key_b64": self.signing_public_b64,
        }


def _private_key_path(key_dir, device_id, name):
    return Path(key_dir) / f"{device_id}_{name}_private.pem"


def _save_private_key(path, key):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _load_private_key(path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_or_create_device_keys(device_id, key_dir):
    ecdh_path = _private_key_path(key_dir, device_id, "ecdh")
    signing_path = _private_key_path(key_dir, device_id, "ed25519")

    if ecdh_path.exists():
        ecdh_private_key = _load_private_key(ecdh_path)
    else:
        ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
        _save_private_key(ecdh_path, ecdh_private_key)

    if signing_path.exists():
        signing_private_key = _load_private_key(signing_path)
    else:
        signing_private_key = ed25519.Ed25519PrivateKey.generate()
        _save_private_key(signing_path, signing_private_key)

    return DeviceKeys(device_id, ecdh_private_key, signing_private_key)


def load_ecdh_public_key(public_key_b64):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64d(public_key_b64))


def load_signing_public_key(public_key_b64):
    return ed25519.Ed25519PublicKey.from_public_bytes(b64d(public_key_b64))
