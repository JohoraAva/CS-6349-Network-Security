from utils import *

  

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
def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """
    Decrypt a message encrypted with rsa_encrypt
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# def decrypt_message(private_key, ciphertext: bytes):
#     # print(f"[Debug] Decrypting message: {ciphertext}")

#     # The RSA-encrypted AES key is the first block
#     # Length = RSA modulus size in bytes = ceil(key_size / 8)
#     rsa_key_size = (private_key.key_size + 7) // 8
#     enc_key = ciphertext[:rsa_key_size]

#     # AES-GCM nonce is 12 bytes
#     nonce = ciphertext[rsa_key_size:rsa_key_size + 12]

#     # Rest is AES-GCM ciphertext
#     aes_ciphertext = ciphertext[rsa_key_size + 12:]

#     try:
#         # Decrypt AES key using RSA private key
#         aes_key = private_key.decrypt(
#             enc_key,
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None
#             )
#         )
#     except Exception as e:
#         print(" RSA decrypt error:", e)
#         raise

#     aesgcm = AESGCM(aes_key)

#     try:
#         # Decrypt the AES-GCM ciphertext
#         plaintext = aesgcm.decrypt(nonce, aes_ciphertext, None)
#     except Exception as e:
#         print("❌ AES-GCM decrypt error (InvalidTag likely):", e)
#         raise

#     print(f"[Debug] Decrypted message: {plaintext}")
#     return plaintext


def hash_verify(data: bytes, expected_hash: bytes) -> bool:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    computed_hash = digest.finalize()
    return computed_hash == expected_hash

def receive(s,private_key):
    while True:
        try:
            data = s.recv(1024)
            flag,src_id,dst_id, msg = data.split(b"|", 3)
            # print(f"\n[Debug] Received data: flag={flag}, src_id={src_id.decode()}, dst_id={dst_id.decode()}, msg={msg}")
            if flag == b"01":
                p, g, enc = msg.split(b"|",2)
                # calculate session params
                # 1.decrypt using private key, sign verify using src public key, 
                # print(f"[Debug] Processing session establishment request from {src_id.decode()}, msg: {enc}")
                signed_msg = decrypt_message(load_private_key(dst_id.decode()), enc)
                # ts || pub_key || hashed_msg (ts || pub_key)
                print(f"[Debug] Decrypted signed message: {signed_msg}")
                recovered_from_sign= unsign_message(load_public_key(src_id.decode()), signed_msg)
                ts, session_pub_key_bytes, hashed_msg_bytes = recovered_from_sign.split(b"|",2)
                ts_decoded = ts.decode()
                rehashed_msg = ts_decoded + int.from_bytes(session_pub_key_bytes, "big")
                # verify hash
                if hash_verify(rehashed_msg, hashed_msg_bytes.decode()):
                    print(f"[{dst_id.decode()}] Session establishment request verified from {src_id.decode()}")
                session_establish_response(s,dst_id.decode(),src_id.decode(),private_key)

                
            elif flag == b"10":
                p, g, enc = msg.split(b"|",2)
                # verify session params
                # calculate session params
            elif flag == b"11":
                print(f"\n[{src_id.decode()}]: {msg.decode()}\nid > ", end="")
            else:
                print(f"[{src_id}] Invalid flag")
        except:
            break

def client():
    s, id, private_key = establish_socket()
    reg_status = send_registration(s, id, private_key)
    if not reg_status:
        print("Registration failed.")
        s.close()
        return
    threading.Thread(target=receive, args=(s,private_key,), daemon=True).start()

    while True:
        dst_id = input("id > ").strip()
        if dst_id.lower() == "exit":
            print("Exiting...")
            msg = ""
        else:
            msg = input("Message: ").strip()
        if msg == "session init":
            session_establish_request(s, id, dst_id, private_key)
        else:
            s.sendall(f"11|{id}|{dst_id}|{msg}".encode())
        if dst_id.lower() == "exit":
            break
    s.close()

if __name__ == "__main__":
    client()
