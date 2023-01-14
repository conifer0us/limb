import socket

HOST = input("Where is your remote limb server? ")
PORT = 6969  # Default Limb Port

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        s.sendall(b"Hello, world")
        data = s.recv(1024)
        print(f"Received {data!r}")