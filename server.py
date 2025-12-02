from utils import *


clients = {} 
lock = threading.Lock()

relay_private_key = load_private_key("Relay")

def send_to_client(target_id, message):
    with lock:
        client_socket = clients[target_id]

    if not client_socket:
        print(f"[Relay] No such client: {target_id}")
        return
    try:
        print(f"[Relay] Sent to client {target_id}")
        client_socket.sendall(message)
    except Exception as e:
        print(f"[Relay] Error sending to client {target_id}: {e}")


def handle_client(c, addr):

    try:
        while True:
            data = c.recv(4096)
            id_str = ""
            if not data:
                return
            flag, rest = data.split(b"|", 1)
            if flag == b"0":
                id, reg_msg, signed_msg = rest.split(b"|", 2)
                id_str = id.decode()
                print(f"[Relay] Registration request from {id_str}")
                public_key = load_public_key(id_str)
                if verify_signature(public_key, reg_msg, signed_msg):
                    print(f"[Relay] Signature verified for {id_str}")
                else:
                    print(f"[Relay] Signature verification failed for {id_str}")
                    return
                with lock:
                    clients[id_str] = c
                    print(f"[Relay] Registered client {id_str}")
                # Prepare and send registration response
                resp_id = b"Relay"
                resp_msg = b"Accept"
                signed_resp_msg = sign_message(relay_private_key, resp_msg)

                response = flag + b"|" + resp_id + b"|" + resp_msg + b"|" + signed_resp_msg
                c.sendall(response)
                print(f"[Relay] Registration response sent to {id_str}")
            else :
                src_id, dst_id, msg = rest.split(b"|", 2)
                src_id_str = src_id.decode()
                dst_id_str = dst_id.decode()
                if dst_id_str=="exit":
                    print(f"[Relay] {src_id_str} leaving")
                    return
                print(f"[Relay] Message from {src_id_str} to {dst_id_str}")
                chat = flag + b"|" + src_id + b"|"+ dst_id + b"|"+ msg
                send_to_client(dst_id_str, chat)
    except Exception as e:
        print("[Relay] Error handling messaging:", e)
        return
    

def all_client(s):
    while True:
        c, addr = s.accept()
        threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()
        # c.close()



def relay():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(50)
    threading.Thread(target=all_client, args=(s,), daemon=True).start()
    while True:
        msg = input()
        if msg == "exit":
            s.close()
            break

if __name__ == "__main__":
    relay()
