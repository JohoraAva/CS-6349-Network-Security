import os
import socket
import threading
import sys
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '127.0.0.1'
PORT = 5555
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

def unsign_message(public_key, signature: bytes) -> bytes:
    try:
        recovered = public_key.recover_data_from_signature(
            signature,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())  # or the hash you used
        )
        return recovered
    except Exception as e:
        raise ValueError("Message cannot be recovered from this signature") from e



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
    private_key = int.from_bytes(os.urandom(256), byteorder='big') % p
    public_key = pow(g, private_key, p)
    return public_key, private_key

# def encrypt_message(public_key, message: bytes) :
#     # Hybrid RSA-AES: encrypt a random AES key with the recipient's RSA public key,
#     # then encrypt the message with AES-GCM. Receiver must know RSA key size and nonce length.
#     aes_key = os.urandom(32)  # 256-bit AES key
#     aesgcm = AESGCM(aes_key)
#     nonce = os.urandom(12)  # recommended 96-bit nonce for GCM
#     ciphertext = aesgcm.encrypt(nonce, message, None)

#     enc_key = public_key.encrypt(
#         aes_key,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return enc_key + nonce + ciphertext

def encrypt_message(public_key, message: bytes) -> bytes:
    """
    Encrypt a message with RSA public key directly.
    WARNING: Only works for small messages < key_size - padding overhead
    """
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def session_establish_request(s: socket.socket, src_id_str: str, dst_id_str: str, private_key) :
    flag = b"01"
    src_id = src_id_str.encode()
    dst_id = dst_id_str.encode()
    sess_msg = b"Session establishment request from " + src_id + b" to " + dst_id
    # timestamp 
    ts = str(time.time()).encode()
    # generate session key using DH
    p,g = get_dh_params()
    pub_key, priv_key = generate_dh_keypair(p, g)
    # hash(ts || pub_key)
    hash_input = ts + pub_key.to_bytes((pub_key.bit_length() + 7) // 8, byteorder='big')
    hashed_msg = hash(hash_input)
    # print(type(ts), type(pub_key), type(hashed_msg))
    pub_key = pub_key.to_bytes((pub_key.bit_length() + 7) // 8, byteorder='big')
    # pub_bytes = pub_key.public_bytes(
    # encoding=serialization.Encoding.DER,
    # format=serialization.PublicFormat.SubjectPublicKeyInfo)


    sign_msg_input = ts +pub_key + hashed_msg.to_bytes(32, byteorder='big', signed=True)
    signed_msg = sign_message(private_key, sign_msg_input)
    dest_pub_key = load_public_key(dst_id_str)
    enc_msg = encrypt_message(dest_pub_key, signed_msg)
    # encrypt signed_msg with B's public key
    # signed_msg = sign_message(private_key, sess_msg)
    # print("type: ", type(flag), type(src_id), type(dst_id), type(p), type(g), type(enc_msg))

    p_bytes_len = (p.bit_length() + 7) // 8   # 256 bytes for 2048-bit p
    g_bytes_len = (g.bit_length() + 7) // 8   # 1 byte for g=2

    # payload = flag + b"|" + src_id + b"|" + dst_id + b"|" + p.to_bytes(p_bytes_len, byteorder='big', signed=False)+ "|"+g.to_bytes(g_bytes_len, byteorder='big', signed=False)+ "|"+ enc_msg
    p_bytes = p.to_bytes(p_bytes_len, byteorder='big', signed=False)
    g_bytes = g.to_bytes(g_bytes_len, byteorder='big', signed=False)
    payload = (
    flag + b"|" + src_id + b"|" + dst_id + b"|" +
    len(p_bytes).to_bytes(2,'big') + p.to_bytes(p_bytes_len, byteorder='big', signed=False) +
    len(g_bytes).to_bytes(1,'big') + g.to_bytes(g_bytes_len, byteorder='big', signed=False) +
    enc_msg)
    # print(payload)
    s.sendall(payload)
    print(f"[+] Session establishment request sent from {src_id_str} to {dst_id_str}")

def session_establish_response(s: socket.socket, src_id_str: str, dst_id_str: str, private_key) :
    flag = b"10"
    src_id = src_id_str.encode()
    dst_id = dst_id_str.encode()
    ts = str(time.time()).encode()
    p,g = get_dh_params()
    pub_key, priv_key = generate_dh_keypair(p, g)
    hash_input = ts + pub_key.to_bytes((pub_key.bit_length() + 7) // 8, byteorder='big')
    hashed_msg = hash(hash_input)
    pub_key = pub_key.to_bytes((pub_key.bit_length() + 7) // 8, byteorder='big')


    sign_msg_input = ts +pub_key + hashed_msg.to_bytes(32, byteorder='big', signed=True)
    signed_msg = sign_message(private_key, sign_msg_input)
    dest_pub_key = load_public_key(dst_id_str)
    enc_msg = encrypt_message(dest_pub_key, signed_msg)

    p_bytes_len = (p.bit_length() + 7) // 8   # 256 bytes for 2048-bit p
    g_bytes_len = (g.bit_length() + 7) // 8   # 1 byte for g=2

    p_bytes = p.to_bytes(p_bytes_len, byteorder='big', signed=False)
    g_bytes = g.to_bytes(g_bytes_len, byteorder='big', signed=False)
    payload = (
    flag + b"|" + src_id + b"|" + dst_id + b"|" +
    len(p_bytes).to_bytes(2,'big') + p.to_bytes(p_bytes_len, byteorder='big', signed=False) +
    len(g_bytes).to_bytes(1,'big') + g.to_bytes(g_bytes_len, byteorder='big', signed=False) +
    enc_msg)
    s.sendall(payload)
    print(f"[+] Session establishment response sent from {src_id_str} to {dst_id_str}")