import os
import socket
import threading
import sys
import time
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

    # print("here4")
    # Recover AES key
    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # print("here5")
    aesgcm = AESGCM(aes_key)
    # print("here6")
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    # print("here7")
    # print("# ", plaintext)
    return plaintext

def hashyyy(hash_input):
    return hash_input


#global_vars
def session_establish_request(s: socket.socket, src_id: str, dst_id: str, private_key):
    flag = b"01"
    ts_req = f"{time.time():024.6f}".encode()
    print("# ts_req : ", len(ts_req))

    # generate session key using DH
    p, g = get_dh_params()
    R_pub, R_pri = generate_dh_keypair(p, g)

    R_pub_b = R_pub.to_bytes((R_pub.bit_length() + 7) // 8, "big")
    # print("# R_pub_b : ", len(R_pub_b))

    hash_input = ts_req + R_pub_b
    hashed_msg = hashyyy(hash_input)

    # sign_input = ts_req + b"|" + R_pub_b + b"|" + hashed_msg.to_bytes(32, "big", signed=True)

    print(f"sign kortese {src_id}")
    signed_msg = hash_input + sign_message(private_key, hashed_msg)



    # print("# msg: ", ts_req+R_pub_b)
    # print("# msg: ", hashed_msg)
    # print("# msg: ", sign_message(private_key, hashed_msg))

    dst_pub = load_public_key(dst_id)
    enc_msg = encrypt_message(dst_pub, signed_msg)

    # print("# enc_msg: ", enc_msg)

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
    return R_pub, R_pri

def handle_session_establish_request(data: bytes, src_id: str, dst_id: str, private_key):

    p_bytes    = data[:256]
    g_bytes    = data[256:257]
    enc_msg    = data[257:]


    # ---------- 2. Reconstruct DH parameters ----------
    p = int.from_bytes(p_bytes, "big")
    g = int.from_bytes(g_bytes, "big")

    signed_msg = decrypt_message(private_key, enc_msg)

    ts_req = signed_msg[:24]
    R_pub_b = signed_msg[24:24+256]
    signed_part = signed_msg[24+256:]

    # print("# ts_req: ", ts_req)
    # print("# R_pub_b: ", R_pub_b)
    # print("# signed_part: ", signed_part)
    # msg = signed_msg[:18+256]

    # print(f"sign kortese {src_id}")
    # print("# msg: ", ts_req+R_pub_b)
    # # print("# msg: ", hashyyy(ts_req+R_pub_b))
    # print("# msg: ", signed_part)
    # print()

    # signed_msg format:
    # ts_req | R_pub | hashed_msg
    #
    # But ts_req has variable length, R_pub has variable length, so the request
    # used a "|" separator.

    # print("de--------bisldkj")


    valid_signature = verify_signature(load_public_key(src_id),hashyyy(ts_req+R_pub_b),signed_part)
    if valid_signature:
        print(f"[{dst_id}] Signature verification succeeded for request from {src_id}")

    # ---------- 6. Reconstruct R_pub ----------
    R_pub = int.from_bytes(R_pub_b, "big")

    if valid_signature == False:
        return None


    # shared_session_key = calculate_session_key(R_pub, R_pri, p)
    return src_id, dst_id, p, g, ts_req.decode(), R_pub

def session_establish_response(s: socket.socket, src_id: str, dst_id: str, private_key):
    flag = b"10"
    ts_req = str(time.time()).encode()

    # generate session key using DH
    p, g = get_dh_params()
    R_pub, R_pri = generate_dh_keypair(p, g)

    R_pub_b = R_pub.to_bytes((R_pub.bit_length() + 7) // 8, "big")

    hash_input = ts_req + b"|" + R_pub_b
    hashed_msg = hash(hash_input)

    sign_input = ts_req + b"|" + R_pub_b + b"|" + hashed_msg.to_bytes(32, "big", signed=True)
    signed_msg = sign_message(private_key, sign_input)

    dst_pub = load_public_key(dst_id)
    enc_msg = encrypt_message(dst_pub, signed_msg)

    p_bytes = p.to_bytes((p.bit_length() + 7) // 8, "big")
    g_bytes = g.to_bytes((g.bit_length() + 7) // 8, "big")

    payload = b"|".join([
        flag,
        src_id.encode(),
        dst_id.encode(),
        p_bytes,
        g_bytes,
        enc_msg
    ])

    s.sendall(payload)
    print(f"[+] Session establishment response sent from {src_id} to {dst_id}")




def calculate_session_key(their_pub: int, my_pri: int, p: int) -> bytes:
    print("Calculating session key..., their_pub : ", their_pub, ", my_pri : ", my_pri, ", p : ", p)
    shared_secret = pow(their_pub, my_pri, p)
    print("shared_secret : ", shared_secret)
    session_key = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    print("Session key calculated.")
    return session_key