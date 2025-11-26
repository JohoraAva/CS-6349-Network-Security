from utils import *
import time
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes



def send_registration(s: socket.socket, id: str, private_key):
    flag = b"00"
    id_bytes = id.encode()
    reg_msg = b"Registration info for " + id_bytes
    signed_msg = sign_message(private_key, reg_msg)
    payload = flag + b"|" + id_bytes + b"|" + reg_msg + b"|" + signed_msg
    s.sendall(payload)
    print(f"[+] Registration request sent by {id}")
    data = s.recv(4096)  # wait for response
    # print("hello2: ", data.decode())
    flag, sender_id, resp_msg, signed_resp = data.split(b"|", 3)
    sender_id_str = sender_id.decode()
    if verify_signature(load_public_key(sender_id_str), resp_msg, signed_resp):
        print(f"[{id}] Registration Response from {sender_id_str}: {resp_msg.decode()}")
        return True
    else:
        print(f"[{id}] Signature verification failed for response from {sender_id_str}")
    return False


def establish_socket():
    id = input("Enter your id (Alice/Bob): ").strip()
    private_key = load_private_key(id)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print(f"Connected to server at {HOST}:{PORT}")
    return s, id, private_key

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

def session_establish(s: socket.socket, id: str, dest_id: str, private_key) :
    flag = b"01"  # session establishment flag
    id_bytes = id.encode()
    dest_id_bytes = dest_id.encode()
    sess_msg = b"Session establishment request from " + id_bytes + b" to " + dest_id_bytes
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
    dest_pub_key = load_public_key(dest_id)
    enc_msg = encrypt_message(dest_pub_key, signed_msg)
    # encrypt signed_msg with B's public key
    # signed_msg = sign_message(private_key, sess_msg)
    # print("type: ", type(flag), type(id_bytes), type(dest_id_bytes), type(p), type(g), type(enc_msg))

    p_bytes_len = (p.bit_length() + 7) // 8   # 256 bytes for 2048-bit p
    g_bytes_len = (g.bit_length() + 7) // 8   # 1 byte for g=2

    # payload = flag + b"|" + id_bytes + b"|" + dest_id_bytes + b"|" + p.to_bytes(p_bytes_len, byteorder='big', signed=False)+ "|"+g.to_bytes(g_bytes_len, byteorder='big', signed=False)+ "|"+ enc_msg
    p_bytes = p.to_bytes(p_bytes_len, byteorder='big', signed=False)
    g_bytes = g.to_bytes(g_bytes_len, byteorder='big', signed=False)
    payload = (
    flag + b"|" + id_bytes + b"|" + dest_id_bytes + b"|" +
    len(p_bytes).to_bytes(2,'big') + p.to_bytes(p_bytes_len, byteorder='big', signed=False) +
    len(g_bytes).to_bytes(1,'big') + g.to_bytes(g_bytes_len, byteorder='big', signed=False) +
    enc_msg)
    s.sendall(payload)
    print(f"[+] Session establishment request sent from {id} to {dest_id}")

is_received = False
def receive(s):
    while True:
        try:
            is_received = True
            data = s.recv(1024)
            flag, send_id, msg = data.split(b"|", 2)
            print(f"\n[{send_id.decode()}]: {msg.decode()}\nid > ")
        except:
            break

def client():
    s, id, private_key = establish_socket()
    reg_status = send_registration(s, id, private_key)
    if not reg_status:
        print("Registration failed.")
        s.close()
        return
    threading.Thread(target=receive, args=(s,), daemon=True).start()
    # if not received anything 
    # if not is_received:
    # dest = input("Enter destination id for session establishment: ").strip()
    # print("Session Establishment Request from {id} to {dest}")
    # # if received 
    # else:
        # print("Session established. You can now send messages.")
    # session_establish(s, id, dest, private_key)

    while True:
        dest_id = input("id > ").strip()
        if dest_id.lower() == "exit":
            print("Exiting...")
            break
        msg = input("Message: ").strip()
        if msg == "session init":
            session_establish(s, id, dest_id, private_key)
        chat = b"11" + b"|" + dest_id.encode() + b"|" + msg.encode()
        s.sendall(chat)
    s.close()

if __name__ == "__main__":
    client()
