import ssl
import socket

def start_client():
    context = ssl.create_default_context()
    context.load_verify_locations("server.pem")
    with socket.create_connection(("localhost", 12345)) as sock:
        with context.wrap_socket(sock, server_hostname="localhost") as ssock:
            while True:
                msg = input("Enter message: ")
                ssock.sendall(msg.encode())
                data = ssock.recv(1024)
                print(f"Received: {data.decode()}")

if __name__ == "__main__":
    start_client()
