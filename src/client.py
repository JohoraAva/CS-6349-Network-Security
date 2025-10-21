import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import threading
# ===============================
# Ask user for identity
# ===============================
IDENTITY = input("Enter your identity (Alice/Bob): ").strip()
PRIVATE_KEY_PATH = f"/home/ava/Courses/CS6349-NetworkSecurity/Project/NS- Project/src/Keys/{IDENTITY.lower()}_rsa"

# Load private key
with open(PRIVATE_KEY_PATH, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

# Sign a message using RSA private key
def sign_message(message: bytes) -> bytes:
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

# Send registration request to relay
def reg_req(sock):
    flag = b"00"  # registration flag
    identity = IDENTITY.encode()
    reg_msg = b"Registration info for " + identity

    signed_msg = sign_message(reg_msg)

    payload = flag + b"|" + identity + b"|" + signed_msg
    sock.sendall(payload)
    print(f"[+] Registration request sent by {IDENTITY}")

# Thread to continuously receive messages from relay
def receive_messages(sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                continue
            flag, identity, signed_msg = data.split(b"|", 2)
            print(f"[{IDENTITY}] Registration Response from {identity.decode()}")  # truncated
        except Exception as e:
            print("Error receiving data:", e)
            break
# ===============================
# MAIN CLIENT
# ===============================
if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 5555))  # Relay server IP and port
    reg_req(sock)
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    # Main loop for sending further messages
    while True:
        msg = input()
        if msg.lower() == "exit":
            print("Exiting...")
            break
        sock.sendall(msg.encode())

    # Optionally close socket on exit
    sock.close()

