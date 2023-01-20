# Class responsible for sending packets from the client to the server

import socket
from limbutils.LimbCrypto import LimbCrypto
from limbutils.limbclientlib.InterfaceController import InterfaceController
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from limbutils.limbclientlib.LimbClientDB import LimbClientDB 
from hashlib import sha256
from limbutils.UsernameFormat import UsernameFormat

class ClientPacketController:

    hostname : str
    port : int
    cryptograpy : LimbCrypto
    serverpubkey : _RSAPublicKey
    interface : InterfaceController
    clientID: bytes
    database : LimbClientDB
    

    # Initializes Client Packet Controller with a hostname, port, interface, and cryptography component
    def __init__(self, hostname : str, port : int, interfaceController : InterfaceController, cryptographylib : LimbCrypto, database : LimbClientDB) -> None:
        self.hostname = hostname
        self.port = port
        self.database = database
        self.interface = interfaceController
        self.cryptograpy = cryptographylib
        self.clientID = sha256(self.cryptograpy.getPubKeyBytes()).digest()
        self.serverpubkey = self.getServerPublicKey()

    # CONNECTION 1 IMPLEMENTATION: Gets the Server Public Key and Returns it as a Public Key Object
    def getServerPublicKey(self) -> _RSAPublicKey:
        rawdata = self.GetRawDataPacket(bytes([1]) + self.cryptograpy.getPubKeyBytes())
        return self.cryptograpy.decodePubKeyBytes(rawdata)
    
    # CONNECTION 2 IMPLEMENTATION: Sends a Username to Register with the Server
    def registerUsername(self, username : str) -> bytes:
        if not UsernameFormat.is_properly_formatted(username):
            return b'Incorrect Name Format'
        asciiname = username.encode('ascii')
        return self.sendSignedPacket(2, asciiname)

    # CONNECTION 3 IMPLEMENTATION: Registers a New Message Board with the Server
    def registerNewMessageBoard(self, boardname : str) -> bytes:
        if not UsernameFormat.is_properly_formatted(boardname):
            return b'Incorrect Name Format'
        asciiboardname = boardname.encode("ascii")
        serverKey = LimbCrypto.generate_aes_key()
        serverkeyhash = sha256(serverKey).digest() 
        packet = serverkeyhash + asciiboardname
        conn = self.sendSignedPacket(3, packet)
        self.database.addBoardToDB(serverkeyhash, boardname, serverKey)
        return conn

    # CONNECTION 4 IMPLEMENTATION: Gets User Public Key from Username
    def getUserKey(self, username : str) -> bytes:
        if not UsernameFormat.is_properly_formatted(username):
            return b'Incorrect Name Format'
        asciiname = username.encode('ascii')
        userkey = self.sendSignedPacket(4, asciiname)
        uid = sha256(userkey).hexdigest()
        try:
            self.cryptograpy.decodePubKeyBytes(userkey)
            self.database.addUsersToDB(uid, username, userkey)
            return userkey
        except:
            return None

    # Returns a UserID for a Username; returns None if the User does not exist
    def getUserID(self, username : str) -> bytes:
        id = self.database.getUserIDByName(username)
        if id:
            return id
        id = self.getUserKey(username)
        if not id:
            return None
        return sha256(id).digest()

    # CONNECTION 5 IMPLEMENTATION: Invites Another User to Join a Board by Username
    def inviteUserToBoard(self, username, boardname):
        boardID = self.database.getBoardIDByName(boardname)
        if not boardID:
            return b'Board Not Found'
        peerID = self.getUserID(username)
        if not peerID:
            return b'User Not Found'
        keybytes = self.database.getUserKeyByName(username)
        key = self.cryptograpy.decodePubKeyBytes(keybytes)
        packet_data = boardID + peerID + self.cryptograpy.encryptData(self.database.getBoardKeyByID(boardID), key)
        return self.sendSignedPacket(5, packet_data) 

    # CONNECTION 6 IMPLEMENTATION: Gets a User's Invite By Id
    def getInviteData(self, inviteid : int):
        return_invite = self.sendSignedPacket(6, bytes([inviteid]), encryption_expected=True)
        if return_invite == b'':
            return None
        server_id = return_invite[0:32]
        server_key = self.cryptograpy.decryptData(return_invite[32:288])
        server_name = return_invite[288:].decode("ascii")
        self.database.addBoardToDB(server_id, server_name, server_key)

    # CONNECTION 7 IMPLEMENTATION: Posts a Message to the Server
    def postMessage(self, message : str, boardname : str):
        boardID = self.database.getBoardIDByName(boardname)
        if not boardID:
            print("There is no board with that name.")
            return b''
        messagebytes = message.encode()
        boardkey = self.database.getBoardKeyByID(boardID)
        packetdata = boardID + LimbCrypto.aes_encrypt(messagebytes, boardkey, self.cryptograpy.getPubKeyBytes())
        return self.sendSignedPacket(7, packetdata, encryption_expected=True) 

    # A Function that Works on top of GetRawDataPacket to Sign Messages before being Sent. Returns bytes data for response
    def sendSignedPacket(self, connectiontype : int, binarydata : bytes, encryption_expected = True) -> bytes:
        rawpacket = bytes([connectiontype]) + (
            self.cryptograpy.encryptData(self.clientID, self.serverpubkey) + 
            self.cryptograpy.encryptData(
                self.cryptograpy.signSmallData(binarydata), self.serverpubkey) + 
            self.cryptograpy.encryptData(binarydata, self.serverpubkey)
            )
        return self.GetRawDataPacket(rawpacket, encryption_expected=encryption_expected)
    
    # Gets a Raw Data Packet from the Server and Decrypts it Using the Client Private Key
    def GetRawDataPacket(self, binarydata : bytes, encryption_expected = True) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.hostname, self.port))
            s.send(binarydata)
            receivedData = s.recv(4096)
            if encryption_expected:
                return self.cryptograpy.decryptData(receivedData)
            else:
                return receivedData