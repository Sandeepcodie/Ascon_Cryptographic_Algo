import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from hmac import compare_digest


def ascon_encrypt(key, nonce, associateddata, plaintext):
    assert len(key) == 16 and len(nonce) == 16
    S = [0, 0, 0, 0, 0]
    a, b, rate = 12, 6, 8
    ascon_initialize(S, a, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    ciphertext = ascon_process_plaintext(S, b, rate, plaintext)
    tag = ascon_finalize(S, a, key)
    return ciphertext + tag


def ascon_decrypt(key, nonce, associateddata, combined):
    assert len(key) == 16 and len(nonce) == 16 and len(combined) >= 16
    ciphertext = combined[:-16]
    received_tag = combined[-16:]
    S = [0, 0, 0, 0, 0]
    a, b, rate = 12, 6, 8
    ascon_initialize(S, a, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    plaintext = ascon_process_ciphertext(S, b, rate, ciphertext)
    calculated_tag = ascon_finalize(S, a, key)
    if not compare_digest(received_tag, calculated_tag):
        raise ValueError("Authentication failed: invalid ASCON tag")
    return plaintext


def ascon_initialize(S, a, key, nonce):
    iv = bytes.fromhex("80400c0600000000")
    initial_state = iv + key + nonce
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(initial_state)
    ascon_permutation(S, a)
    zero_key = bytes_to_state(b"\x00" * (40 - len(key)) + key)
    for i in range(5):
        S[i] ^= zero_key[i]


def ascon_process_associated_data(S, b, rate, associateddata):
    if len(associateddata) > 0:
        ad_lastlen = len(associateddata) % rate
        ad_zero_bytes = rate - (ad_lastlen % rate) - 1
        ad_padding = bytes([0x80] + [0x00] * ad_zero_bytes)
        ad_padded = associateddata + ad_padding
        for block in range(0, len(ad_padded), rate):
            S[0] ^= int(ad_padded[block:block + 8].hex(), 16)
            ascon_permutation(S, b)
    S[4] ^= 1


def ascon_process_plaintext(S, b, rate, plaintext):
    p_lastlen = len(plaintext) % rate
    p_zero_bytes = (rate - p_lastlen) - 1
    p_padding = bytes([0x80] + [0x00] * p_zero_bytes)
    p_padded = plaintext + p_padding
    ciphertext = bytes([])
    blocks = len(p_padded) - rate
    for block in range(0, blocks, rate):
        S[0] ^= int(p_padded[block:block + 8].hex(), 16)
        ciphertext += S[0].to_bytes(8, "big")
        ascon_permutation(S, b)
    p_last = int(p_padded[blocks:].hex(), 16)
    S[0] ^= p_last
    ciphertext += S[0].to_bytes(8, "big")[:p_lastlen]
    return ciphertext


def ascon_process_ciphertext(S, b, rate, ciphertext):
    c_lastlen = len(ciphertext) % rate
    c_zero_bytes = (rate - c_lastlen) - 1
    c_padding = bytes([0x80] + c_zero_bytes * [0x00])
    c_padded = ciphertext + c_padding
    plaintext = bytes([])
    blocks = len(c_padded) - rate
    for block in range(0, blocks, rate):
        ci = int(c_padded[block:block + 8].hex(), 16)
        plaintext += (S[0] ^ ci).to_bytes(8, "big")
        S[0] = ci
        ascon_permutation(S, b)
    c_last = int(c_padded[blocks:].hex(), 16)
    plaintext += (c_last ^ S[0]).to_bytes(8, "big")[:c_lastlen]
    padded_plaintext = int((plaintext[blocks:] + c_padding).hex(), 16)
    S[0] ^= padded_plaintext
    return plaintext


def ascon_finalize(S, a, key):
    assert len(key) == 16
    S[1] ^= int(key[:8].hex(), 16)
    S[2] ^= int(key[8:].hex(), 16)
    ascon_permutation(S, a)
    S[3] ^= int(key[:8].hex(), 16)
    S[4] ^= int(key[8:].hex(), 16)
    return S[3].to_bytes(8, "big") + S[4].to_bytes(8, "big")


def ascon_permutation(S, rounds):
    assert rounds <= 12
    for r in range(12 - rounds, 12):
        S[2] ^= 0xF0 - r * 0x10 + r
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i + 1) % 5] for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0xFFFFFFFFFFFFFFFF
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2], 1) ^ rotr(S[2], 6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4], 7) ^ rotr(S[4], 41)


def bytes_to_state(data):
    hex_data = data.hex()
    return [int(hex_data[16 * w:16 * (w + 1)], 16) for w in range(5)]


def rotr(val, r):
    return (val >> r) | ((val & (1 << r) - 1) << (64 - r))


def b64e(data):
    return base64.b64encode(data).decode("ascii")


def b64d(data):
    return base64.b64decode(data.encode("ascii"))


P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (P256_GX, P256_GY)
POINT_INFINITY = None


def is_on_curve(point):
    if point is POINT_INFINITY:
        return True
    x, y = point
    if not (0 <= x < P256_P and 0 <= y < P256_P):
        return False
    return (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P == 0


def point_add(point1, point2):
    if point1 is POINT_INFINITY:
        return point2
    if point2 is POINT_INFINITY:
        return point1
    x1, y1 = point1
    x2, y2 = point2
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return POINT_INFINITY
    if point1 == point2:
        slope = ((3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P)) % P256_P
    else:
        slope = ((y2 - y1) * pow(x2 - x1, -1, P256_P)) % P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    y3 = (slope * (x1 - x3) - y1) % P256_P
    return x3, y3


def scalar_mult(scalar, point):
    if scalar % P256_N == 0 or point is POINT_INFINITY:
        return POINT_INFINITY
    if not is_on_curve(point):
        raise ValueError("Point is not on the P-256 curve")
    result = POINT_INFINITY
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def int_to_32_bytes(value):
    return value.to_bytes(32, "big")


def generate_ecdh_private_key():
    return secrets.randbelow(P256_N - 1) + 1


def public_key_bytes(private_key):
    x, y = scalar_mult(private_key, P256_G)
    return b"\x04" + int_to_32_bytes(x) + int_to_32_bytes(y)


def load_public_key(public_key_data):
    if len(public_key_data) != 65 or public_key_data[0] != 0x04:
        raise ValueError("Expected a 65-byte uncompressed P-256 public key")
    point = (
        int.from_bytes(public_key_data[1:33], "big"),
        int.from_bytes(public_key_data[33:65], "big"),
    )
    if not is_on_curve(point):
        raise ValueError("Public key is not on P-256 curve")
    return point


def hkdf_sha256(input_key_material, salt, info, length):
    pseudorandom_key = hmac.new(salt, input_key_material, hashlib.sha256).digest()
    output = b""
    previous = b""
    block_number = 1
    while len(output) < length:
        previous = hmac.new(
            pseudorandom_key,
            previous + info + bytes([block_number]),
            hashlib.sha256,
        ).digest()
        output += previous
        block_number += 1
    return output[:length]


def derive_ascon_key(private_key, peer_public_key_b64, session_id, first_id, second_id):
    peer_public_key = load_public_key(b64d(peer_public_key_b64))
    shared_point = scalar_mult(private_key, peer_public_key)
    if shared_point is POINT_INFINITY:
        raise ValueError("Invalid ECDH shared point")
    shared_secret = int_to_32_bytes(shared_point[0])
    info = b"|".join([
        b"ECDH HKDF ASCON-128 MQTT",
        session_id,
        first_id.encode("utf-8"),
        second_id.encode("utf-8"),
    ])
    return hkdf_sha256(shared_secret, salt=session_id, info=info, length=16)


def make_associated_data(sender_id, receiver_id, session_id, counter):
    data = {
        "counter": counter,
        "receiver_id": receiver_id,
        "sender_id": sender_id,
        "session_id": session_id.hex(),
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def make_nonce(session_id, counter):
    return session_id[:8] + counter.to_bytes(8, "big")


@dataclass
class SecureDevice:
    device_id: str
    peer_id: str
    private_key: int
    session_id: bytes | None = None
    ascon_key: bytes | None = None
    send_counter: int = 0
    last_received_counter: int = 0

    @classmethod
    def create(cls, device_id, peer_id):
        return cls(device_id, peer_id, generate_ecdh_private_key())

    def public_key_message(self):
        return {
            "device_id": self.device_id,
            "public_key_b64": b64e(public_key_bytes(self.private_key)),
        }

    def establish_session(self, peer_public_key_b64, session_id):
        self.session_id = session_id
        first_id = min(self.device_id, self.peer_id)
        second_id = max(self.device_id, self.peer_id)
        self.ascon_key = derive_ascon_key(
            self.private_key,
            peer_public_key_b64,
            session_id,
            first_id,
            second_id,
        )

    def encrypt_message(self, plaintext):
        if self.ascon_key is None or self.session_id is None:
            raise ValueError("Session is not established")
        self.send_counter += 1
        counter = self.send_counter
        nonce = make_nonce(self.session_id, counter)
        ad = make_associated_data(self.device_id, self.peer_id, self.session_id, counter)
        combined = ascon_encrypt(self.ascon_key, nonce, ad, plaintext)
        return {
            "sender_id": self.device_id,
            "receiver_id": self.peer_id,
            "session_id": self.session_id.hex(),
            "counter": counter,
            "nonce_b64": b64e(nonce),
            "associated_data_b64": b64e(ad),
            "ciphertext_b64": b64e(combined[:-16]),
            "tag_b64": b64e(combined[-16:]),
        }

    def decrypt_message(self, packet):
        if self.ascon_key is None or self.session_id is None:
            raise ValueError("Session is not established")
        if packet.get("sender_id") != self.peer_id:
            raise ValueError("Wrong sender id")
        if packet.get("receiver_id") != self.device_id:
            raise ValueError("Wrong receiver id")
        counter = int(packet["counter"])
        if counter <= self.last_received_counter:
            raise ValueError("Replay attack rejected")
        if packet["session_id"] != self.session_id.hex():
            raise ValueError("Wrong session id")
        nonce = b64d(packet["nonce_b64"])
        expected_nonce = make_nonce(self.session_id, counter)
        if not compare_digest(nonce, expected_nonce):
            raise ValueError("Wrong nonce")
        ad = b64d(packet["associated_data_b64"])
        expected_ad = make_associated_data(
            packet["sender_id"],
            packet["receiver_id"],
            self.session_id,
            counter,
        )
        if not compare_digest(ad, expected_ad):
            raise ValueError("Wrong associated data")
        combined = b64d(packet["ciphertext_b64"]) + b64d(packet["tag_b64"])
        plaintext = ascon_decrypt(self.ascon_key, nonce, ad, combined)
        self.last_received_counter = counter
        return plaintext
