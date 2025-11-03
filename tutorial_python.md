# Python Resources for Socket Programming with Multithreading #
https://www.geeksforgeeks.org/python/socket-programming-python/ \
https://www.geeksforgeeks.org/python/multithreading-python-set-1/
## Basic Socket Programming ##
### Server ###
```python
import socket
# declare libraries

HOST = '127.0.0.1'
PORT = 4390
# fix server address

s = socket.socket()         
# declare socket

s.bind((HOST, PORT))
# bind socket to a host and a port

s.listen(5)     
# listen and set buffer size; can accept at most 5 clients

c, addr = s.accept()     
print ('Got connection from', addr )
# wait and accept client trying to connect

c.close()
# close connection 
```
### Client ###
```python
import socket
# declare libraries

HOST = '127.0.0.1'
PORT = 4390
# fix server address

s = socket.socket()       
# declare socket

s.connect((HOST, PORT))
# connect to server at address  

s.close()
# close connection 
```
## Single Message Exchange ##
### Server ###
```python
import socket

HOST = '127.0.0.1'
PORT = 4390
s = socket.socket()         
s.bind((HOST, PORT))
s.listen(5)     
c, addr = s.accept()     
print ('Got connection from', addr )

c.send('Thank you for connecting'.encode())
# send message to client
print(c.recv(1024).decode())
# read contents sent by client

c.close()
```
### Client ###
```python
import socket

HOST = '127.0.0.1'
PORT = 4390
s = socket.socket()       
s.connect((HOST, PORT))

print(s.recv(1024).decode())
# read contents sent by server 
s.send('Okay bye!'.encode())
# send message to server

s.close()
```
## Uninterrupted Dual Mode Messaging ##
### Server ###
```python
import socket
import threading

HOST = '127.0.0.1'
PORT = 4392

def send(c):
    while True:
        msg = input()
        c.sendall(msg.encode())
# send thread 

def receive(c):
    while True:
        msg = c.recv(1024)
        print(f"{msg.decode()}")
# receive thread 

s = socket.socket()         
s.bind((HOST, PORT))
s.listen(5)     
c, addr = s.accept()     
print ('Got connection from', addr )

t1 = threading.Thread(target=send, args=(c,))
t2 = threading.Thread(target=receive, args=(c,))
t1.start()
t2.start()
t1.join()
t2.join()

c.close()
```
### Client ###
```python
import socket
import threading

HOST = '127.0.0.1'
PORT = 4392

def send(s):
    while True:
        msg = input()
        s.sendall(msg.encode())
# send thread 

def receive(s):
    while True:
        msg = s.recv(1024)
        print(f"{msg.decode()}")
# receive thread 

s = socket.socket()       
s.connect((HOST, PORT))

t1 = threading.Thread(target=receive, args=(s,))
t2 = threading.Thread(target=send, args=(s,))
t1.start()
t2.start()
t1.join()
t2.join()


s.close()
```
## Multi Client Chat ###
### Server ###
```python
import socket
import threading

HOST = '127.0.0.1'
PORT = 5555

clients = {} 
client_id_counter = 1
lock = threading.Lock()

def handle_client(c, addr, client_id):
    print(f"[Client {client_id}] Connected from {addr}")
    c.sendall(f"Your ID is {client_id}".encode())
    while True:
        try:
            data = c.recv(1024)
            print(f"Client {client_id}: {data.decode()}")
        except:
            break
    c.close()
    with lock:
        del clients[client_id]
        print(f"[Client {client_id}] removed.")

def send_to_client():
    while True:
        try:
            raw = input("")
            parts = raw.split(" ", 1)
            if len(parts) < 2:
                print("Usage: <client_id> <message>")
                continue

            target_id, msg = parts
            try:
                target_id = int(target_id)
            except ValueError:
                print("Invalid client ID.")
                continue

            with lock:
                if target_id in clients:
                    clients[target_id].sendall(msg.encode())
                else:
                    print(f"No such client: {target_id}")
        except KeyboardInterrupt:
            break


s = socket.socket()
s.bind((HOST, PORT))
s.listen(5)

threading.Thread(target=send_to_client, daemon=True).start()

while True:
    c, addr = s.accept()
    with lock:
        cid = client_id_counter
        clients[cid] = c
        client_id_counter += 1
    threading.Thread(target=handle_client, args=(c, addr, cid), daemon=True).start()
```
### Client ###
```python
import socket
import threading

HOST = '127.0.0.1'
PORT = 5555

def receive(s):
    while True:
        try:
            data = s.recv(1024)
            print(f"\nServer: {data.decode()}")
        except:
            break

def send(s):
    while True:
        msg = input("")
        s.sendall(msg.encode())

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
print(f"Connected to server at {HOST}:{PORT}")

threading.Thread(target=receive, args=(s,), daemon=True).start()
send(s)
```