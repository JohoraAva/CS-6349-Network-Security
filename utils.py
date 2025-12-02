import os
import socket
import threading
import sys
import time
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '127.0.0.1'
PORT = 5552
KEYS_DIR = "keys"
RELAY_PRIVATE_KEY_PATH = "keys/relay_rsa"

def ensure_keys_exist(id: str):
    os.makedirs(KEYS_DIR, exist_ok=True)
    private_key_path = os.path.join(KEYS_DIR, f"{id.lower()}_rsa")
    public_key_path = os.path.join(KEYS_DIR, f"{id.lower()}_rsa.pub")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print(f"[KeyGen] Keys for '{id}' already exist.")
        return private_key_path
    
    os.makedirs("keys", exist_ok=True)
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

def get_dh_params():
    # Using predefined 2048-bit MODP Group from RFC 3526
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
        "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC"
        "6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F"
        "24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361"
        "C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552"
        "BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C329"
        "05E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06"
        "F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051"
        "015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    g = 2
    return p, g

def generate_dh_keypair(p: int, g: int):
    R_pri = int.from_bytes(os.urandom(256), byteorder='big') % p
    R_pub = pow(g, R_pri, p)
    return R_pub, R_pri

# def compute_shared_key(ur_pub: int, my_pri: int, p: int) -> int:
#     return pow(ur_pub, my_pri, p)
def compute_shared_key(ur_pub: int, my_pri: int, p: int) -> bytes:
    shared_int = pow(ur_pub, my_pri, p)
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")
    derived_key = hashlib.sha256(shared_bytes).digest()
    return derived_key

def encrypt_message(public_key, message: bytes) :
    # Hybrid RSA-AES: encrypt a random AES key with the recipient's RSA public key,
    # then encrypt the message with AES-GCM. Receiver must know RSA key size and nonce length.
    aes_key = os.urandom(32)  # 256-bit AES key
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # recommended 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, message, None)

    enc_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return enc_key + nonce + ciphertext

def decrypt_message(private_key, data: bytes):
    """
    Reverse of encrypt_message():
    data format = enc_key || nonce || ciphertext

    - enc_key: RSA-encrypted AES key (length = RSA modulus size in bytes)
    - nonce: 12 bytes
    - ciphertext: AES-GCM encrypted payload
    """

    rsa_key_size = private_key.key_size // 8  # size in bytes (e.g., 2048 bits → 256 bytes)
    enc_key = data[:rsa_key_size]
    nonce = data[rsa_key_size:rsa_key_size + 12]
    ciphertext = data[rsa_key_size + 12:]

    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

def hashyyy(hash_input):
    return hash_input


#global_vars
def session_establish_request(s: socket.socket, src_id: str, dst_id: str, private_key):
    flag = b"1"
    ts_req = f"{time.time():024.6f}".encode()

    p, g = get_dh_params()
    req_pub, req_pri = generate_dh_keypair(p, g)

    req_pub_b = req_pub.to_bytes((req_pub.bit_length() + 7) // 8, "big")

    hash_input = ts_req + req_pub_b
    hashed_msg = hashyyy(hash_input)

    signed_msg = hash_input + sign_message(private_key, hashed_msg)

    dst_pub = load_public_key(dst_id)
    enc_msg = encrypt_message(dst_pub, signed_msg)

    p_bytes = p.to_bytes((p.bit_length() + 7) // 8, "big")
    g_bytes = g.to_bytes((g.bit_length() + 7) // 8, "big")

    payload = b"|".join([
        flag,
        src_id.encode(),
        dst_id.encode(),
        p_bytes+
        g_bytes+
        enc_msg
    ])

    s.sendall(payload)
    print(f"[+] Session establishment request sent from {src_id} to {dst_id}")
    return req_pub, req_pri, p, g

def handle_session_establish_request(data: bytes, src_id: str, dst_id: str, private_key):

    p_bytes    = data[:256]
    g_bytes    = data[256:257]
    enc_msg    = data[257:]

    p = int.from_bytes(p_bytes, "big")
    g = int.from_bytes(g_bytes, "big")

    signed_msg = decrypt_message(private_key, enc_msg)

    ts_req = signed_msg[:24]
    req_pub_b = signed_msg[24:24+256]
    signed_part = signed_msg[24+256:]


    valid_signature = verify_signature(load_public_key(src_id),hashyyy(ts_req+req_pub_b),signed_part)
    if valid_signature:
        print(f"[{dst_id}] Signature verification succeeded for request from {src_id}")

    req_pub = int.from_bytes(req_pub_b, "big")

    if valid_signature == False:
        return None

    return p, g, ts_req.decode(), req_pub

def session_establish_response(s: socket.socket, src_id: str, dst_id: str, private_key, res_pub):
    flag = b"2"
    ts_res = f"{time.time():024.6f}".encode()

    res_pub_b = res_pub.to_bytes((res_pub.bit_length() + 7) // 8, "big")

    hash_input = ts_res + res_pub_b
    hashed_msg = hashyyy(hash_input)

    signed_msg = hash_input + sign_message(private_key, hashed_msg)
    dst_pub = load_public_key(dst_id)

    enc_msg = encrypt_message(dst_pub, signed_msg)


    payload = b"|".join([
        flag,
        src_id.encode(),
        dst_id.encode(),
        enc_msg
    ])

    s.sendall(payload)
    print(f"[+] Session establishment response sent from {src_id} to {dst_id}")

def handle_session_establish_response(data: bytes, src_id: str, dst_id: str, private_key):

    enc_msg    = data

    signed_msg = decrypt_message(private_key, enc_msg)

    ts_res = signed_msg[:24]
    res_pub_b = signed_msg[24:24+256]
    signed_part = signed_msg[24+256:]

    valid_signature = verify_signature(load_public_key(src_id),hashyyy(ts_res+res_pub_b),signed_part)
    if valid_signature:
        print(f"[{dst_id}] Signature verification succeeded for request from {src_id}")

    res_pub = int.from_bytes(res_pub_b, "big")

    if valid_signature == False:
        return None

    return ts_res.decode(), res_pub

def encrypt_with_shared_key(shared_key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt with AES-256-GCM.
    shared_key = 32 bytes (256-bit)
    Returns: nonce || ciphertext
    """
    if len(shared_key) != 32:
        raise ValueError("shared_key must be 32 bytes (256-bit)")

    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)     # GCM standard nonce length
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # caller stores/transmits this


def decrypt_with_shared_key(shared_key: bytes, data: bytes) -> bytes:
    """
    Decrypt AES-256-GCM.
    Input = nonce || ciphertext
    """
    if len(shared_key) != 32:
        raise ValueError("shared_key must be 32 bytes (256-bit)")

    nonce = data[:12]
    ciphertext = data[12:]

    aesgcm = AESGCM(shared_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext