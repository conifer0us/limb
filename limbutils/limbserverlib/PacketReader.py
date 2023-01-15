# Class for Reading Packets coming into the Server. Understands Message Types and Handles Them.

from limbutils.limbserverlib.LimbLogger import LimbLogger
from limbutils.LimbCrypto import LimbCrypto
from limbutils.limbserverlib.LimbDB import LimbDB
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey

class PacketReader:
    # The Following Array Defines the Functions That Handle Certain Types of Packets

    logger : LimbLogger

    cryptography : LimbCrypto

    db : LimbDB

    packet_function_mapping = {} 

    # Initializes the Packet Handler with objects that must be used to accomplish its tasks. Allows the PacketReader to register things in the database as well as perform cryptography operations and log events. 
    def __init__(self, logger : LimbLogger, crypto : LimbCrypto, db : LimbDB) -> None:
        self.logger = logger
        self.cryptography = crypto
        self.db = db
        # Defines what Functions the Server Should Call When it Receives a Packet Based on the First Byte of the Packet
        self.packet_function_mapping = { 
            1 : self.pubkey_welcome
        }

    # A Method that interpret's packet data and calls the corresponding method on that data according to the type of request that is being processed
    def parse_packet(self, bytearray : bytes) -> bytes:
        packetMode = int(bytearray[0])
        try:
            return self.packet_function_mapping[packetMode](bytearray[1:])
        except KeyError:
            self.logger.registerEvent("FAIL", f"Attempted Connection Did not Contain Proper Packet Type.")
            return b''

    # A Method that Handles Type 1: Establish Requests. It takes a Public Key from a User, registers the User using the DB class, and returns the server's public key, encrypted with the client's supplied key to aid further communication.
    def pubkey_welcome(self, bytearray : bytes) -> bytes:
        client_pub_key = None
        try:
            client_pub_key = self.cryptography.decodePubKeyBytes(bytearray)
        except:
            self.logger.registerEvent("FAIL", f"Establish Packet Received But Public Key Failed to Decode")
            return b''
        self.logger.registerEvent("EST", f"Establish Packet Received From Public Key {str(bytearray[1:])}. Response sent. Connection Closed.")
        self.db.registerKey(client_pub_key)
        return self.EncryptWithClientKey(self.cryptography.getPubKeyBytes(), client_pub_key) 

    # A Simple Method that Encrypts a Message With the Key Supplied by the Client
    def EncryptWithClientKey(self, messagebytes : bytes, client_key : _RSAPublicKey) -> bytes:
        encdata = self.cryptography.encryptData(messagebytes, client_key)
        return encdata