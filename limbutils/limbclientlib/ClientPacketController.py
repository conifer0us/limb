import socket
from limbutils.LimbCrypto import LimbCrypto
from limbutils.limbclientlib.InterfaceController import InterfaceController
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey

class ClientPacketController:

    hostname : str
    port : int
    cryptograpy : LimbCrypto
    serverpubkey = None
    interface : InterfaceController

    # Initializes Client Packet Controller with a hostname, port, interface, and cryptography component
    def __init__(self, hostname : str, port : int, interfaceController : InterfaceController, cryptographylib : LimbCrypto) -> None:
        self.hostname = hostname
        self.port = port
        self.interface = interfaceController
        self.cryptograpy = cryptographylib

    # Gets the Server Public Key and Returns it as a Public Key Object
    def getServerPublicKey(self) -> _RSAPublicKey:
        rawdata = self.GetRawDataPacketWithEncryption(bytes([1]) + self.cryptograpy.getPubKeyBytes())
        print(rawdata)
        return self.cryptograpy.decodePubKeyBytes(rawdata)
        
    # Gets a Raw Data Packet from the Server and Decrypts it Using the Client Private Key
    def GetRawDataPacketWithEncryption(self, binarydata : bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.hostname, self.port))
            self.interface.showInformation("Connected Successfully")
            s.send(binarydata)
            return self.cryptograpy.decryptData(s.recv(4096))