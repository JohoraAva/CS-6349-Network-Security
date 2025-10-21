import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Load Relay's private key
RELAY_PRIVATE_KEY_PATH = f"/home/ava/Courses/CS6349-NetworkSecurity/Project/NS- Project/src/Keys/relay_rsa"
with open(RELAY_PRIVATE_KEY_PATH, "rb") as key_file:
    relay_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

def sign_message(message: bytes) -> bytes:
    signature = relay_private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def handle_client(conn):
    data = conn.recv(4096)
    if not data:
        return

    try:
        # Parse registration request
        flag, identity, signed_msg = data.split(b"|", 2)
        if flag == b"00":
            print(f"[Relay] Registration request from {identity.decode()}")
            # print(f"[Relay] Signed message length: {len(signed_msg)} bytes")

            # Prepare registration response
            resp_flag = b"00"
            resp_identity = b"Relay"
            resp_msg = b"Accept"
            signed_resp_msg = sign_message(resp_msg)

            payload = resp_flag + b"|" + resp_identity + b"|" + signed_resp_msg
            conn.sendall(payload)
            print(f"[Relay] Registration response sent to {identity.decode()}")

    except Exception as e:
        print("Error handling registration:", e)

# Simple relay server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 5555))
server.listen()
print("[Relay] Listening for clients...")

while True:
    conn, addr = server.accept()
    handle_client(conn)
    conn.close()
