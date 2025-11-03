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

def receive(s):
    while True:
        try:
            data = s.recv(1024)
            send_id, msg = data.split(b"|", 1)
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

    while True:
        send_id = input("id > ").strip()
        if send_id.lower() == "exit":
            print("Exiting...")
            break
        msg = input("Message: ").strip()
        s.sendall(f"{send_id}|{msg}".encode())
    s.close()

if __name__ == "__main__":
    client()
