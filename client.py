from utils import *


# Global variables  
session_keys = {}
req_pri = {}
p = {}
g = {}
lock = threading.Lock()


def send_registration(s: socket.socket, src_id: str, private_key):
    flag = b"0"
    src_id_bytes = src_id.encode()
    reg_msg = b"Registration info for " + src_id_bytes
    signed_msg = sign_message(private_key, reg_msg)
    payload = flag + b"|" + src_id_bytes + b"|" + reg_msg + b"|" + signed_msg
    s.sendall(payload)
    print(f"[+] Registration request sent by {src_id}")
    data = s.recv(4096)  # wait for response

    flag, sender_id, resp_msg, signed_resp = data.split(b"|", 3)
    sender_id_str = sender_id.decode()
    if verify_signature(load_public_key(sender_id_str), resp_msg, signed_resp):
        print(f"[{id}] Registration Response from {sender_id_str}: {resp_msg.decode()}")
        return True
    else:
        print(f"[{id}] Signature verification failed for response from {sender_id_str}")
    return False


def establish_socket():
    id = input("Enter your id (Alice/Bob): ").strip().capitalize()
    private_key = load_private_key(id)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print(f"Connected to server at {HOST}:{PORT}")
    return s, id, private_key

def receive(s,private_key):
    while True:
        try:
            data = s.recv(4096)
            flag,src_id_b,dst_id_b, msg = data.split(b"|", 3)
            src_id = src_id_b.decode().capitalize()
            dst_id = dst_id_b.decode().capitalize()
            if flag == b"1":
                print(f"[{src_id}] Session establishment request received.")
                #p,g, requester's timestamp, requester's public key
                p_, g_ = get_dh_params()
                ts_req, req_pub = handle_session_establish_request(msg, src_id, dst_id, private_key, True)
                with lock:
                    p[src_id] = p_
                    g[src_id] = g_
                    # Generate responder key pair
                    res_pub, res_pri = generate_dh_keypair(p[src_id], g[src_id])
                    session_keys[src_id] = compute_shared_key(req_pub,res_pri,p[src_id])
                enc_msg = session_establish_request(s, dst_id, src_id, private_key, res_pub)
                payload = b"|".join([b"2",dst_id.encode(),src_id.encode(),enc_msg])
                s.sendall(payload)
                print(f"[+] Session establishment response sent from {dst_id} to {src_id}")
                with lock:
                    print(f"[{dst_id}] Session established with {src_id}. Shared session key: {session_keys[src_id]}")
            elif flag == b"2":
                print(f"[{src_id}] Session establishment response received.")
                ts_res, res_pub = handle_session_establish_request(msg, src_id, dst_id, private_key)
                with lock:
                    session_keys[src_id] = compute_shared_key(res_pub,req_pri[src_id],p[src_id])
                    print(f"[{dst_id}] Session established with {src_id}. Shared session key: {session_keys[src_id]}")
            elif flag == b"3":
                with lock:
                    # received encrypted message
                    msg = hmac_ctr_decrypt(session_keys[src_id],msg)
                print(f"\n[{src_id}]: {msg.decode()}\nid > ", end="")
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
        dst_id = input("id > ").strip().capitalize()
        if dst_id.lower() == "exit":
            print("Exiting...")
            exit(0)
            msg = ""
        else:
            msg = input("Message: ").strip()
        if msg == "init_session":
            # global pub_key, pri_key
            p_, g_ = get_dh_params()
            req_pub, req_pri_ = generate_dh_keypair(p_, g_)
            enc_msg = session_establish_request(s, id, dst_id, private_key, req_pub, True)

            p_bytes = p_.to_bytes((p_.bit_length() + 7) // 8, "big")
            g_bytes = g_.to_bytes((g_.bit_length() + 7) // 8, "big")
           
            payload = b"|".join([b"1",id.encode(),dst_id.encode(),p_bytes+g_bytes+enc_msg])
            s.sendall(payload)
            print(f"[+] Session establishment request sent from {id} to {dst_id}")
            with lock:
                req_pri[dst_id.capitalize()] = req_pri_
                p[dst_id.capitalize()] = p_
                g[dst_id.capitalize()] = g_
        else:
            with lock:
                sk = session_keys.get(dst_id)
            if sk is None:
                print(f"[!] Please establish session keys with {dst_id} first")
            else:
                with lock:
                    ciphertext = hmac_ctr_encrypt(session_keys[dst_id],msg.encode())
                s.sendall(f"3|{id}|{dst_id}|".encode()+ciphertext)
        if dst_id.lower() == "exit":
            break
    s.close()

if __name__ == "__main__":
    client()
