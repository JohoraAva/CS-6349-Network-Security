from utils import *
import sys

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
    data = c.recv(4096)
    id_str = ""
    if not data:
        return

    try:
        # id, reg_msg, signed_msg = data.split(b"|", 3)
        flag, rest = data.split(b"|", 1)
        if flag == b"00":
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
            resp_flag = b"00"
            resp_id = b"Relay"
            resp_msg = b"Accept"
            signed_resp_msg = sign_message(relay_private_key, resp_msg)

            response = resp_flag + b"|" + resp_id + b"|" + resp_msg + b"|" + signed_resp_msg
            c.sendall(response)
            print(f"[Relay] Registration response sent to {id_str}")
        elif flag in (b"01", b"10"):
            # forwarding messages
            id_str = id.decode()
        #    print(f"[Relay] Session establishment request from {id_str} to ...")
            try:
                # Expecting: flag|from|to|ts|pub_key|enc_msg
                parts = rest.split(b"|", 4)  # limit splits so enc_msg may contain '|'
                if len(parts) < 5:
                    print(f"[Relay] Malformed session request from {id_str}")
                else:
                    src_b, dest_b, p , g , enc_msg = parts
                    src = src_b.decode()
                    dest = dest_b.decode()
                    print(f"[Relay] Session establishment request from {src} to {dest}")
                    # forward the original payload to destination if connected
                    with lock:
                        dest_sock = clients.get(dest)
                    if not dest_sock:
                        print(f"[Relay] Destination {dest} not registered")
                    else:
                        try:
                            dest_sock.sendall(data)
                            print(f"[Relay] Forwarded session request from {src} to {dest}")
                        except Exception as e:
                            print(f"[Relay] Error forwarding to {dest}: {e}")
            except Exception as e:
                print("[Relay] Error handling session request:", e)
                return
            


    except Exception as e:
        print("[Relay] Error handling registration:", e)
        return
    try:
        while True:
            msg_data = c.recv(4096)
            if not msg_data:
                break
            flag, tail = msg_data.split(b"|", 1)
            if flag == b"00":
                dest, msg = tail.split(b"|", 1)
                dest_str = dest.decode()
                print(f"[Relay] Message from {id_str} to {dest_str}")
                # chat = id + b"|"+ msg
                # send_to_client(rec_id_str, chat)
            elif flag == b"10" or flag == b"01":
                src, dest, msg = tail.split(b"|", 2)
                # msg = msg_data.split(b"|", 1)
                print(f"[Relay] Session message from {src.decode()} to {dest.decode()}")
                dest_str = dest.decode()
                # print(f"[Relay] Message from {id_str} to {dest_str}")
            # chat = src + b"|" + enc_msg_b64
            chat = flag + b"|" + id + b"|"+ msg
            send_to_client(dest_str, chat)
    except Exception as e:
        print("[Relay] Error handling messaging:", e)
        return
    



def relay_close(sock: socket.socket):
    # cmd = exit 
    try :
        cmd = input("Type 'exit' to quit: ").strip().lower()
        if cmd.lower() == "exit":
            print("Shutting down relay...")
            socket_close(sock)
            print("Relay shut down.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\n[INFO] Keyboard interrupt detected. Closing all sockets...")
        for s in sockets_list:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            s.close()
        sys.exit(0)

def relay():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(50)


    try:
        while True:
            c, addr = s.accept()
            threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()

    except KeyboardInterrupt:
        print("[Relay] Shutdown requested.")

    finally:
        s.close()
        print("[Relay] Server closed.")

if __name__ == "__main__":
    relay()
