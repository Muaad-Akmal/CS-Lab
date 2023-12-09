import ssl
import socket
from threading import Thread

def handle_client(conn, addr):
    print(f"New connection from {addr}")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        print(f"Received from {addr}: {data.decode()}")
        conn.sendall(data)
    conn.close()

def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.pem", keyfile="server.key")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(("localhost", 12345))
        sock.listen()
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                conn, addr = ssock.accept()
                thread = Thread(target=handle_client, args=(conn, addr))
                thread.start()





if __name__ == "__main__":
    start_server()



# openssl req -new -key server.key -out server.csr -subj "/CN=localhost"

# server.pem = public
#server.key = private