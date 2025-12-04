import os
import socket
import threading
import sys
import time
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Tuple, Optional
import hmac
import math

HOST = '127.0.0.1'
PORT = 5552
KEYS_DIR = "keys"
RELAY_PRIVATE_KEY_PATH = "keys/relay_rsa"

#global variables
lock = threading.Lock()
BLOCK_SIZE = 32  # AES block size in bytes
max_age_seconds = 60 # maximum age for timestamps in seconds

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


def load_public_key(id: str):
    public_key_path = os.path.join(KEYS_DIR, f"{id.lower()}_rsa.pub")
    with open(public_key_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())







def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
    






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

def encrypt_message(public_key, message: bytes) : #rsa encryption
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

def decrypt_message(private_key, data: bytes): #rsa decryption
    """
    Reverse of encrypt_message():
    data format = enc_key || nonce || ciphertext

    - enc_key: RSA-encrypted AES key (length = RSA modulus size in bytes)
    - nonce: 12 bytes
    - ciphertext: AES-GCM encrypted payload
    """

    #split data
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






def _hash_sha256(hash_input):
    return hashlib.sha256(hash_input).hexdigest().encode()


def check_timestamp_freshness(ts: int) -> bool:
    now = int(time.time())
    if ts > now + 5:
        return False
    if now - ts > max_age_seconds:
        return False
    return True

def session_establish_request(s: socket.socket, src_id: str, dst_id: str, private_key, pub_key, is_req: bool =False):
    flag = b"1"
    ts_req = f"{time.time():024.6f}".encode()


    pub_key_b = pub_key.to_bytes((pub_key.bit_length() + 7) // 8, "big")

    hash_input = ts_req + pub_key_b
    hashed_msg = _hash_sha256(hash_input)

    signed_msg = hash_input + sign_message(private_key, hashed_msg)

    dst_pub = load_public_key(dst_id)
    enc_msg = encrypt_message(dst_pub, signed_msg)

   
    return enc_msg


def handle_session_establish_request(data: bytes, src_id: str, dst_id: str, private_key, is_req: bool = False):

    if is_req:
        p_bytes    = data[:256]
        g_bytes    = data[256:257]
        enc_msg    = data[257:]

        p = int.from_bytes(p_bytes, "big")
        g = int.from_bytes(g_bytes, "big")
    else:
        enc_msg    = data

    
    signed_msg = decrypt_message(private_key, enc_msg)

    ts_req = signed_msg[:24]
    req_pub_b = signed_msg[24:24+256]
    signed_part = signed_msg[24+256:]


    #verify ts freshness
    if not check_timestamp_freshness(int(float(ts_req.decode()))):
        return None

    #verify signature
    valid_signature = verify_signature(load_public_key(src_id),_hash_sha256(ts_req+req_pub_b),signed_part)
    if valid_signature:
        print(f"[{dst_id}] Signature verification succeeded for request from {src_id}")

    req_pub = int.from_bytes(req_pub_b, "big")

    if valid_signature == False:
        return None

    return ts_req.decode(), req_pub






def compute_shared_key(ur_pub: int, my_pri: int, p: int) -> bytes:
    shared_int = pow(ur_pub, my_pri, p)
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")
    derived_key = hashlib.sha256(shared_bytes).digest()
    return derived_key






def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def derive_count0(session_key: bytes, message_index: int = 0) -> int:
    # calculate count0 = HMAC(session_key, "count0" || message_index)
    msg = b"count0" + message_index.to_bytes(4, "big")
    digest = _hmac_sha256(session_key, msg)
    # reduce to 64-bit integer to be a practical counter
    return int.from_bytes(digest[:8], "big")

def generate_keystream(session_key: bytes, nonce: bytes, count0: int, n_blocks: int) -> bytes:
    """
    Generate n_blocks * BLOCK_SIZE bytes of keystream by computing
    Ksi = HMAC(session_key, nonce || counti_bytes) for i in [0..n_blocks-1].
    counti_bytes is 8-byte big-endian.
    """
    ks = bytearray()
    for i in range(n_blocks):
        counti = count0 + i
        data = nonce + int.to_bytes(counti, 8, "big")
        ks_block = _hmac_sha256(session_key, data)
        ks.extend(ks_block)
    return bytes(ks[: n_blocks * BLOCK_SIZE])


def hmac_ctr_encrypt(session_key: bytes,plaintext: bytes, message_index: int = 0): #encrypt with session key
    """
    Encrypt plaintext using HMAC-CTR with timestamp prefix.
    """
    nonce = os.urandom(16)  # 128-bit nonce; size can be adjusted
    ts = int(time.time())  # unix seconds
    # Format timestamp as 8-byte big-endian integer
    ts_bytes = ts.to_bytes(8, "big")
    msg_with_ts = ts_bytes + len(plaintext).to_bytes(4, "big") + plaintext

    # hash msg
    hashed_msg = _hash_sha256(msg_with_ts)
    msg_to_encrypt =  msg_with_ts + hashed_msg

    # split into blocks of BLOCK_SIZE
    n_blocks = math.ceil(len(msg_to_encrypt) / BLOCK_SIZE)
    count0 = derive_count0(session_key, message_index)
    keystream = generate_keystream(session_key, nonce, count0, n_blocks)

    # XOR to produce ciphertext
    ciphertext = bytes(a ^ b for a, b in zip(msg_to_encrypt, keystream[: len(msg_to_encrypt)]))

    return nonce + ciphertext

def hmac_ctr_decrypt(session_key: bytes,cipher: bytes, msg_idx : int = 0): #decrypt with session key
    # decrypt ciphertext

    nonce = cipher[:16]
    ciphertext = cipher[16:]
    # Recompute count0 and mac to verify
    count0 = derive_count0(session_key, 0)
   
    # compute keystream and XOR to recover ts||plaintext
    n_blocks = math.ceil(len(ciphertext) / BLOCK_SIZE)
    keystream = generate_keystream(session_key, nonce, count0, n_blocks)
    recovered = bytes(a ^ b for a, b in zip(ciphertext, keystream[: len(ciphertext)]))

    if len(recovered) < 8:
        return False, None, None, "Recovered message too short to contain timestamp"

    ts_bytes = recovered[:8]
    ts = int.from_bytes(ts_bytes, "big")
    len_plaintext = int.from_bytes(recovered[8:12], "big")
    plaintext = recovered[12:12+len_plaintext]

    # verify hash
    hashed_msg = _hash_sha256(recovered[:12+len_plaintext])
    if hashed_msg != recovered[12+len_plaintext:]:
        return False, ts, None, "Hash verification failed"

    # check timestamp freshness
    if not check_timestamp_freshness(ts):
        return False, ts, None, "Timestamp not fresh"

    return plaintext
