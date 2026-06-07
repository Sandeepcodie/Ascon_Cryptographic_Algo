# ASCON Secure Deploy

Deployable secure messaging starter using:

```text
P-256 ECDH shared secret
        |
        v
HKDF-SHA256
        |
        v
128-bit ASCON session key
        |
        v
ASCON authenticated encryption over MQTT
```

This version adds the deployment pieces missing from a simple demo:

- Stable per-device private keys
- P-256 ECDH from Python `cryptography`
- HKDF-SHA256 to a 16-byte ASCON key
- Ed25519 signatures for handshake messages
- Device registry verification
- MQTT username/password support
- MQTT TLS support
- Receiver replay-counter persistence
- Docker Compose starter for a private Mosquitto broker
- Mosquitto ACL example for sender/receiver topic access

## Important Production Note

This is a serious deployable starter, but ASCON itself is still implemented in local Python code. For a high-risk commercial or government system, use an audited ASCON implementation or a formally reviewed library.

## Files

```text
ascon_secure_deploy/
  ascon_security.py          # ASCON encrypt/decrypt implementation
  secure_session.py          # signed ECDH/HKDF/ASCON session layer
  device_keys.py             # stable P-256 + Ed25519 device keys
  registry.py                # trusted device registry
  mqtt_client.py             # MQTT auth/TLS client helper
  state_store.py             # persistent replay counter storage
  generate_device_keys.py    # create keys + registry
  receiver.py
  sender.py
  test_secure_session.py
  docker-compose.yml
  Dockerfile
  deploy/mosquitto/
  requirements.txt
  .env.example
```

## 1. Install Python Requirements

```powershell
pip install -r requirements.txt
```

## 2. Generate Stable Device Keys

```powershell
python generate_device_keys.py
```

This creates:

```text
keys/
device_registry.json
```

The registry contains public keys only. The `keys/` folder contains private keys and must be protected.

## 3. Test Security Flow Locally

```powershell
python test_secure_session.py
```

Expected checks:

- ECDH/HKDF derives the same 128-bit ASCON key on both sides
- ASCON decrypts valid packets
- Replay packets are rejected
- Ciphertext tampering is rejected
- Signed session tampering is rejected

## 4. Run Without Docker Broker

If you already have an MQTT broker:

Receiver terminal:

```powershell
$env:ASCON_MQTT_HOST="your-broker.example.com"
$env:ASCON_MQTT_PORT="8883"
$env:ASCON_MQTT_TLS="true"
$env:ASCON_MQTT_USERNAME="ascon_user"
$env:ASCON_MQTT_PASSWORD="change_this_password"
$env:ASCON_MQTT_CA_FILE="ca.crt"
$env:ASCON_DEVICE_ID="receiver_01"
$env:ASCON_PEER_ID="sender_01"
python receiver.py
```

Sender terminal:

```powershell
$env:ASCON_MQTT_HOST="your-broker.example.com"
$env:ASCON_MQTT_PORT="8883"
$env:ASCON_MQTT_TLS="true"
$env:ASCON_MQTT_USERNAME="ascon_user"
$env:ASCON_MQTT_PASSWORD="change_this_password"
$env:ASCON_MQTT_CA_FILE="ca.crt"
$env:ASCON_DEVICE_ID="sender_01"
$env:ASCON_PEER_ID="receiver_01"
$env:ASCON_MESSAGE="Hello secure ASCON"
python sender.py
```

## 5. Docker Mosquitto Broker

The included `docker-compose.yml` starts Mosquitto. Before production use:

1. Replace `deploy/mosquitto/passwords` with a real password file.
2. Review `deploy/mosquitto/acl` and update the namespace/device IDs if you changed them.
3. Add TLS files:

```text
deploy/mosquitto/certs/ca.crt
deploy/mosquitto/certs/server.crt
deploy/mosquitto/certs/server.key
```

4. Start broker:

```powershell
docker compose up -d
```

To create a Mosquitto password file on a machine with Mosquitto tools:

```powershell
mosquitto_passwd -c deploy/mosquitto/passwords ascon_receiver
mosquitto_passwd deploy/mosquitto/passwords ascon_sender
```

Use `ascon_receiver` for `receiver.py` and `ascon_sender` for `sender.py`.

## 6. What Is Verified

The system verifies:

- Peer public keys are in `device_registry.json`
- Receiver public-key message has a valid Ed25519 signature
- Sender session message has a valid Ed25519 signature
- Session is addressed to the expected sender and receiver IDs
- Sender ECDH public key matches the registry
- Receiver ECDH public key matches the registry
- HKDF output is 16 bytes, so ASCON key is 128-bit
- Packet sender ID and receiver ID
- Session ID
- Monotonic counter
- Nonce
- Associated data
- ASCON authentication tag

## 7. Deployment Checklist

- Use a private MQTT broker.
- Enable TLS.
- Enable MQTT username/password or client certificates.
- Protect `keys/`.
- Keep `ASCON_LOG_SESSION_KEY=false`.
- Keep `device_registry.json` under admin control.
- Use unique topic namespaces.
- Back up receiver state if replay counters must survive server migration.
- Replace the placeholder Mosquitto password file before exposing the broker.
