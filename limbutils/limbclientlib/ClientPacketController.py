import socket
from limbutils.LimbCrypto import LimbCrypto
from limbutils.limbclientlib.InterfaceController import InterfaceController
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from hashlib import sha256

class ClientPacketController:

    hostname : str
    port : int
    cryptograpy : LimbCrypto
    serverpubkey : _RSAPublicKey
    interface : InterfaceController
    clientID: bytes
    

    # Initializes Client Packet Controller with a hostname, port, interface, and cryptography component
    def __init__(self, hostname : str, port : int, interfaceController : InterfaceController, cryptographylib : LimbCrypto) -> None:
        self.hostname = hostname
        self.port = port
        self.interface = interfaceController
        self.cryptograpy = cryptographylib
        self.clientID = sha256(self.cryptograpy.getPubKeyBytes()).digest()
        self.serverpubkey = self.getServerPublicKey()

    # CONNECTION 1 IMPLEMENTATION: Gets the Server Public Key and Returns it as a Public Key Object
    def getServerPublicKey(self) -> _RSAPublicKey:
        rawdata = self.GetRawDataPacket(bytes([1]) + self.cryptograpy.getPubKeyBytes(), encryption_expected=True)
        return self.cryptograpy.decodePubKeyBytes(rawdata)
    
    # CONNECTION 2 IMPLEMENTATION: Sends a Username to Register with the Server
    def registerUsername(self, username : str) -> bytes:
        asciiname = username.encode('ascii')
        rawpacket = bytes([2]) + (
            self.cryptograpy.encryptData(self.clientID, self.serverpubkey) + 
            self.cryptograpy.encryptData(
                self.cryptograpy.signSmallData(asciiname), self.serverpubkey) + 
            self.cryptograpy.encryptData(asciiname, self.serverpubkey)
            )
        return_val = self.GetRawDataPacket(rawpacket, encryption_expected=True)
        return return_val
    
    # Gets a Raw Data Packet from the Server and Decrypts it Using the Client Private Key
    def GetRawDataPacket(self, binarydata : bytes, encryption_expected = False) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.hostname, self.port))
            s.send(binarydata)
            receivedData = s.recv(4096)
            if encryption_expected:
                return self.cryptograpy.decryptData(receivedData)
            else:
                return receivedData