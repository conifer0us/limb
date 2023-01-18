# Class for Reading Packets coming into the Server. Understands Message Types and Handles Them.

from limbutils.limbserverlib.LimbLogger import LimbLogger
from limbutils.LimbCrypto import LimbCrypto
from limbutils.limbserverlib.LimbDB import LimbDB
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from limbutils.UsernameFormat import UsernameFormat

class PacketReader:
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
            1 : self.pubkey_welcome, 
            2 : self.register_username, 
            3 : self.register_server
        }

    # A Method that interpret's packet data and calls the corresponding method on that data according to the type of request that is being processed
    def parse_packet(self, bytearray : bytes) -> bytes:
        packetMode = int(bytearray[0])
        try:
            return self.packet_function_mapping[packetMode](bytearray[1:])
        except KeyError:
            self.logger.registerEvent("FAIL", f"Attempted Connection Did not Contain Proper Packet Type.")
            return b'10'

    # CONNECTION 1 IMPLEMENTATION
    # A Method that Handles Type 1: Establish Requests. It takes a Public Key from a User, registers the User using the DB class, and returns the server's public key, encrypted with the client's supplied key to aid further communication.
    def pubkey_welcome(self, bytearray : bytes) -> bytes:
        client_pub_key = None
        try:
            client_pub_key = self.cryptography.decodePubKeyBytes(bytearray)
        except:
            self.logger.registerEvent("FAIL", f"Establish Packet Received But Public Key Failed to Decode")
            return b'Your Public Key Failed to Decode.'
        self.logger.registerEvent("EST", f"Establish Packet Received From Public Key {str(bytearray[1:])}. Response sent. Connection Closed.")
        self.db.registerKeyHash(bytearray)
        return self.EncryptWithClientKey(self.cryptography.getPubKeyBytes(), client_pub_key) 

    # CONNECTION 2 IMPLEMENTATION
    # Function that Handles Connections of Type 2. Registers Usernames to User IDs
    def register_username(self, bytearray : bytes) -> bytes:
        verified_boolean, uname, client_pubkey_object, uidbytes, signature = self.ReadUIDSignedPacket(bytearray, ascii_encoding=True)
        if not verified_boolean:
            return b'Your signed packet could not be parsed'
        if not UsernameFormat.is_properly_formatted(uname):
            return self.EncryptWithClientKey(b'Username not in the proper format', client_pubkey_object)
        return self.EncryptWithClientKey(self.db.registerUName(uidbytes, signature, uname), client_pubkey_object)

    # CONNECTION 3 IMPLEMENTATION
    # Function that Handles Connections of Type 3. Registers Message Boards to the Server.
    def register_server(self, bytearray : bytes) -> bytes:
        verified_boolean, packetdata, client_pubkey_object, uidbytes, signature = self.ReadUIDSignedPacket(bytearray)
        serverID = packetdata[0:32]
        boardname = packetdata[32:].decode("ascii")
        if not verified_boolean:
            return b'Your signed packet could not be parsed'
        if not UsernameFormat.is_properly_formatted(boardname):
            return self.EncryptWithClientKey(b'Server name not in the proper format.')
        return self.EncryptWithClientKey(self.db.registerMessageBoard(serverID, boardname, uidbytes), client_pubkey_object)


    # Function that Handles Packets that Should Be Signed by a User who has Previously established correct connection with the server
    # RETURNS: verified_boolean, data, client_public_key, client_id, signature
    def ReadUIDSignedPacket(self, bytearray : bytes, ascii_encoding = False):
        try:
            uidbytes = self.cryptography.decryptData(bytearray[0:256])
            id_pubkey = self.db.getPubKeyFromUID(uidbytes)
            client_pubkey_object = self.cryptography.decodePubKeyBytes(id_pubkey)
            signature = self.cryptography.decryptData(bytearray[256:768])
            new_byte_array = self.cryptography.decryptData(bytearray[768:])
            if ascii_encoding:
                new_byte_array = new_byte_array.decode('ascii')
            self.cryptography.verifySignatureData(new_byte_array, signature, client_pubkey_object)
            return True, new_byte_array, client_pubkey_object, uidbytes, signature
        except:
            return False, None, None, None, None

    # A Simple Method that Encrypts a Message With the Key Supplied by the Client
    def EncryptWithClientKey(self, messagebytes : bytes, client_key : _RSAPublicKey) -> bytes:
        encdata = self.cryptography.encryptData(messagebytes, client_key)
        return encdata