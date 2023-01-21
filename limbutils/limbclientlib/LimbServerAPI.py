# Class responsible for sending packets from the client to the server

import socket
from limbutils.LimbCrypto import LimbCrypto
from limbutils.limbclientlib.InterfaceController import InterfaceController
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from limbutils.limbclientlib.LimbClientDB import LimbClientDB 
from hashlib import sha256
from limbutils.UsernameFormat import UsernameFormat

class LimbServerAPI:

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
    
    # Checks if The Database Currently has a Username for the User
    def isUsernameRegistered(self) -> bool:
        return self.database.getUserNameByID(self.clientID)

    # CONNECTION 2 IMPLEMENTATION: Sends a Username to Register with the Server and Logs it Locally under Your Client ID
    def registerUsername(self, username : str) -> bool:
        if self.isUsernameRegistered():
            return True

        # Checks if the Username Supplied is Properly Formatted
        if not UsernameFormat.is_properly_formatted(username):
            return False
        
        asciiname = username.encode('ascii')
        serverdata = self.sendSignedPacket(2, asciiname)
        
        # If the Server Denies the Packet, return False
        if serverdata == b'0':
            return False
        
        # Logs the Current User in the Database
        self.database.addUsersToDB(self.clientID.hex(), username, self.cryptograpy.getPubKeyBytes())

        return True
        

    # CONNECTION 3 IMPLEMENTATION: Registers a New Message Board with the Server
    def registerNewMessageBoard(self, boardname : str) -> bool:

        # Checks if Board Name Follows Naming Conventions (8 characters, Letters and Numbers)
        if not UsernameFormat.is_properly_formatted(boardname):
            return False
        
        asciiboardname = boardname.encode("ascii")
        serverKey = LimbCrypto.generate_aes_key()
        serverkeyhash = sha256(serverKey).digest()
        packet = serverkeyhash + asciiboardname
        
        conn = self.sendSignedPacket(3, packet)
        
        # Returns True if Server Responds b'1' for Completed Operation Successfully
        if conn == b'1':
            self.database.addBoardToDB(serverkeyhash, boardname, serverKey, owner=True)
            return True
        return False

    # CONNECTION 4 IMPLEMENTATION: Gets User Public Key from Username and Registers the User in the Database
    def _getUserKeyFromServer(self, username : str) -> bytes:
        # If Username is Not Properly Formatted, Returns None
        
        if not UsernameFormat.is_properly_formatted(username):
            return None

        asciiname = username.encode('ascii')
        userkey = self.sendSignedPacket(4, asciiname)
        uid = sha256(userkey).hexdigest()

        # If Client Successfully Reads Packet, User Info Added to Database
        try:
            self.cryptograpy.decodePubKeyBytes(userkey)
            self.database.addUsersToDB(uid, username, userkey)
            return userkey
        
        # Returns None if Client cannot Interpret Public Key Data
        except:
            return None

    # Returns a UserID for a Username; returns None if the User does not exist
    def getUserID(self, username : str) -> bytes:
        # First Checks Database for Existing ID and Returns if Found
        id = self.database.getUserIDByName(username)
        if id:
            return id
        
        # Checks Network For ID. Returns if Found and Logs in Database through _getUserKeyFromServer
        id = self._getUserKeyFromServer(username)
        if id:
            return sha256(id).digest()

        # Returns None if Nothing Found
        return None

    # Returns a User Key for a Username
    def getUserKey(self, username : str) -> _RSAPublicKey:
        # First Checks Database for Existing Key and Returns if Found
        key = self.database.getUserKeyByName(username)
        if key:
            return self.cryptograpy.decodePubKeyBytes(key)

        #Checks Network for Key Data. Returns if Found and Logs User in Database through _getUserKeyFromServer
        key = self._getUserKeyFromServer(username)
        if key:
            return self.cryptograpy.decodePubKeyBytes(key)

        # Returns None if Nothing Found
        return None

    # CONNECTION 5 IMPLEMENTATION: Invites Another User to Join a Board by Username
    def inviteUserToBoard(self, username, boardname) -> bool:
        # Checks if Board is Currently in Database
        boardID = self.database.getBoardIDByName(boardname)
        if not boardID:
            return False

        # Checks if User Exists on Server or Locally
        peerID = self.getUserID(username)
        if not peerID:
            return False

        # Checks if User Owns the Board
        if not self.database.ownsBoard(boardID):
            return False

        keybytes = self.database.getUserKeyByName(username)
        key = self.cryptograpy.decodePubKeyBytes(keybytes)
        packet_data = boardID + peerID + self.cryptograpy.encryptData(self.database.getBoardKeyByID(boardID), key)
        
        serverresp = self.sendSignedPacket(5, packet_data) 
        if serverresp == b'1':
            return True
        return False

    # CONNECTION 6 IMPLEMENTATION: Gets a User's Invite By Id
    # Returns True if Invite Data was Succesfully Returned, False if no Data was Returned
    def getInviteData(self, inviteid : int) -> bool:
        serverresp = self.sendSignedPacket(6, bytes([inviteid]), encryption_expected=True)
        
        if serverresp == b'0':
            return False

        # Parse Server Response and Add Board to Boards Database
        server_id = serverresp[0:32]
        server_key = self.cryptograpy.decryptData(serverresp[32:288])
        server_name = serverresp[288:].decode("ascii")
        self.database.addBoardToDB(server_id, server_name, server_key)
        return True

    # CONNECTION 7 IMPLEMENTATION: Posts a Message to the Server
    def postMessage(self, message : str, boardname : str) -> bool:
        # Checks if Board Exists in your Database
        boardID = self.database.getBoardIDByName(boardname)
        if not boardID:
            return False

        # Encrypt Message with AES
        messagebytes = message.encode()
        boardkey = self.database.getBoardKeyByID(boardID)
        packetdata = boardID + LimbCrypto.aes_encrypt(messagebytes, boardkey, self.cryptograpy.getPubKeyBytes())
        
        # See if Server Accepted Message
        serverresp = self.sendSignedPacket(7, packetdata, encryption_expected=True) 
        if serverresp == b'1':
            return True
        return False

    # CONNECTION 8 IMPLEMENTATION: Gets a Message From the Server
    # Returns True if Message Successfully Received, False Otherwise
    def getMessage(self, boardname : str, messageID : int) -> bool:

        # Checks if Board is in User's Database
        boardID = self.database.getBoardIDByName(boardname)
        if not boardID:
            return False

        # Build Packet and Check if Server Accepted Response
        packetdata = boardID + bytes([messageID])
        return_info = self.sendSignedPacket(8, packetdata, encryption_expected=True)
        if return_info == b'0':
            return False

        # Parse Packet if Server Accepted Response
        senderID = return_info[0:32]
        timestamp = return_info[32:40]
        message = LimbCrypto.aes_decrypt(return_info[40:], self.database.getBoardKeyByID(boardID), self.getUserKey(self.getUname(senderID)))
        
        # Add Message to Database and Return True
        self.database.addMessageToDB(boardID, senderID, timestamp, message)
        return True

    # CONNECTION 9 IMPLEMENTATION: Gets a Username From ID Bytes and log user info 
    def getUname(self, id : bytes) -> str:
        # If User in the Database, return the username
        dbid = self.database.getUserNameByID(id)
        if dbid: return dbid

        # Send Packet for Username if Not in Database; If not in Packet, return None
        packetdata = self.sendSignedPacket(9, id, encryption_expected=True)
        if packetdata == b'0':
            return None

        # Return Username Received in Packet
        uname = packetdata.decode('ascii')
        clientkey = self.getUserKey(uname)
        self.database.addUsersToDB(id.hex(), uname, clientkey)
        return uname

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