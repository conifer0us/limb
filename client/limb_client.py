import socket

HOST = "127.0.0.1" # Default Limb Port
PORT = 6969  # Default Limb Port

def send_connection_type(connectionType, socket : socket.socket):
    socket.sendall(bytes([connectionType]))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    send_connection_type(1, s)
    data = s.recv(4096)
    print(f"Received {data!r}")