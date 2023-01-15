import socket

class ClientSocketController:

    hostname : str
    port : int

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port

    def SendRawDataPacket(self, binarydata):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.hostname, self.port))
            s.send(binarydata)
            data = s.recv(4096)
            print(f"Received {data!r}")