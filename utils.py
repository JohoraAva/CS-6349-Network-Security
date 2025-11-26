import os
import socket
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HOST = '127.0.0.1'
PORT = 5565
KEYS_DIR = "keys"
RELAY_PRIVATE_KEY_PATH = "keys/relay_rsa"

def ensure_keys_exist(id: str):
    os.makedirs(KEYS_DIR, exist_ok=True)
    private_key_path = os.path.join(KEYS_DIR, f"{id.lower()}_rsa")
    public_key_path = os.path.join(KEYS_DIR, f"{id.lower()}_rsa.pub")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print(f"[KeyGen] Keys for '{id}' already exist.")
        return private_key_path
    
    os.makedirs("Keys", exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save private key
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"[KeyGen] Key pair saved as:\n  {private_key_path}\n  {public_key_path}")
    return private_key_path

def load_private_key(id: str):
    private_key_path = ensure_keys_exist(id)
    # key_path = f"Keys/{id.lower()}_rsa"
    with open(private_key_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
    
def load_public_key(id: str):
    public_key_path = os.path.join(KEYS_DIR, f"{id.lower()}_rsa.pub")
    with open(public_key_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())



def socket_close(sock: socket.socket):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception as e:
        print(f"[SocketClose] Error during shutdown: {e}")
    finally:
        sock.close()
        print("[SocketClose] Socket closed.")
