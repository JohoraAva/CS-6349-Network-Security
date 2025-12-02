from utils import *

# Global variables  
pub_key = None
pri_key = None
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
            data = s.recv(4096)
            flag,src_id_b,dst_id_b, msg = data.split(b"|", 3)
            src_id = src_id_b.decode()
            dst_id = dst_id_b.decode()
            if flag == b"01":

                # p, g, enc = msg.split(b"|",2)
                print(f"[{src_id}] Session establishment request received.")
                src_id, dst_id, p, g, ts_req, other_pub_key = handle_session_establish_request(msg, src_id, dst_id, private_key)
                print("src_id : " + str(src_id) + ", dst_id : " + str(dst_id) + ", p : " + str(p) + ", g : " + str(g) + ", ts_req : " + str(ts_req) + ", other_pub_key : " + str(other_pub_key))
                # print("# eikhane ashche")
                # calculate session params
                global pri_key
                print("global val(): ", pri_key)
                print("value: ", other_pub_key, get_own_pri_key(), p)
                # shared_key = calculate_session_key(other_pub_key, get_own_pri_key(), p)
                # session_establish_response(s,dst_id,src_id,private_key)

                print(f"[{dst_id}] Session established with {src_id}. Shared session key: {shared_key}")
            elif flag == b"10":
                p, g, enc = msg.split(b"|",2)
                print(f"[{src_id}] Session establishment response received.")
                # verify session params
                # calculate session params
                shared_key = calculate_session_key(other_pub_key, get_own_pri_key(), p)
                print(f"[{dst_id}] Session established with {src_id}. Shared session key: {shared_key}")
            elif flag == b"11":
                print(f"\n[{src_id}]: {msg.decode()}\nid > ", end="")
            else:
                print(f"[{src_id}] Invalid flag")
        except:
            break


#global var, own_pri_key

def set_own_pri_key(pri):
    global pri_key
    print("Setting own pri key: ", pri)
    pri_key = pri

def get_own_pri_key():
    global pri_key
    return pri_key


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
        if msg == "init":
            global pub_key, pri_key
            pub_key,  pri_key = session_establish_request(s, id, dst_id, private_key)
            set_own_pri_key(pri_key)
            print("init : "+str(pub_key)+", "+str(pri_key))
        else:
            s.sendall(f"11|{id}|{dst_id}|{msg}".encode())
        if dst_id.lower() == "exit":
            break
    s.close()

if __name__ == "__main__":
    client()
