# The Limb Client | Connects to Limb Servers

from limbclientlib.ClientSocketController import ClientSocketController

socket = ClientSocketController("127.0.0.1", 6969)

socket.SendRawDataPacket(bytes([1]))