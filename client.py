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

def receive(s,private_key):
    while True:
        try:
            data = s.recv(1024)
            flag,src_id,dst_id, msg = data.split(b"|", 3)
            if flag == b"01":
                p, g, enc = msg.split(b"|",2)
                # calculate session params
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
