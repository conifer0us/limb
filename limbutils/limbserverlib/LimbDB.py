# A Set of Abstractions over the Limb DB

import sqlite3 as sql
from limbutils.limbserverlib.LimbLogger import LimbLogger
from hashlib import sha256
from limbutils.DBUtils import DBUtils
from time import time

class LimbDB:
    db_file = None

    limbLogger : LimbLogger

    database : sql.Connection

    # Creates the Users Table that stores information about UserID, Public Key, Name, and Username Signature
    def createUsersTable(self):
        if not DBUtils.tableExists(self.database, "users"):
            self.database.cursor().execute("CREATE TABLE users (UserID varchar(64) PRIMARY KEY, PubKey varbinary, Uname varchar, UnameSignature varbinary)")
            self.limbLogger.registerEvent("DATA", "No Users Table Found. Creating User Table")
            self.database.commit()

    # Creates the Boards Table that stores information about BoardID, Name, and OwnerID
    def createBoardsTable(self):
        if not DBUtils.tableExists(self.database, "boards"):
            self.database.cursor().execute("CREATE TABLE boards (BoardID varchar(64) PRIMARY KEY, Name varchar(8), OwnerID varchar(64))")
            self.limbLogger.registerEvent("DATA", "No Boards Table Found. Creating Boards Table.")
            self.database.commit()
    
    # Creates a User Boards Table to Store Information About what Boards the User is In. Includes Board ID, Board Key(encrypted with user pubkey), and Board Name
    def createUserBoardsTable(self, uidstring : str):
        if not DBUtils.tableExists(self.database, DBUtils.userdbname(uidstring)):
            self.database.cursor().execute(f"CREATE TABLE {DBUtils.userdbname(uidstring)} (id INTEGER PRIMARY KEY AUTOINCREMENT, Board varchar(64), BoardKey varbinary, BoardName varchar)")
            self.database.commit()
            self.limbLogger.registerEvent("DATA", f"New User Boards Table Created ({DBUtils.userdbname(uidstring)})")

    # Creates a Board Message Table to Store Message Information for the Board. Includes sequential Message ID, Sender ID, Encrypted Message Data, and the SendTime
    def createBoardMessageTable(self, boardidstring): 
        if not DBUtils.tableExists(self.database, DBUtils.boarddbname(boardidstring)):
            self.database.cursor().execute(f"CREATE TABLE {DBUtils.boarddbname(boardidstring)} (id INTEGER PRIMARY KEY AUTOINCREMENT, Sender varchar(64), EncMessage varbinary, SendTime datetime)")
            self.limbLogger.registerEvent("DATA", f"New Message Board Table ({DBUtils.boarddbname(boardidstring)}) Created.")

    # Initializes the Limb DB with a Logger Object to Log Major Changes; Creates Major Changes 
    def __init__(self, db_file : str, logger : LimbLogger) -> None:
        self.limbLogger = logger
        self.database = sql.connect(db_file)
        self.limbLogger.registerEvent("DATA",f"Database file at {db_file} connected.")
        self.createUsersTable()
        self.createBoardsTable()

    # Gets the Public Key that corresponds to the given Username in the users database
    def getPubKeyFromUsername(self, username : str) -> bytes:
        return DBUtils.fetchSingleRecord(self.database, "SELECT PubKey FROM users WHERE Uname=?", (username,))

    # Gets the Username of a user from ID
    def getUsernameFromID(self, uid : bytes):
        uidDigest = uid.hex()
        return_data = DBUtils.fetchSingleRecord(self.database, "SELECT Uname FROM users WHERE UserID=?", (uidDigest,))
        if not return_data: return b'0'
        return return_data.encode("ascii")

    # Gets the Public Key that corresponds to the given User ID in the users database 
    def getPubKeyFromUID(self, uid : bytes) -> bytes:
        uidDigest = uid.hex()
        return DBUtils.fetchSingleRecord("SELECT PubKey FROM users WHERE UserID=?", (uidDigest,))

    # Gets the Name of a Board from its ID
    def getBoardNameFromID(self, boardid : str) -> str:
        return DBUtils.fetchSingleRecord("SELECT Name FROM Boards WHERE BoardID=?", (boardid,))

    # Gets the String Identifier of a Message Board Owner
    def userOwnsBoard(self, uid : str, boardid : str) -> bool:
        return DBUtils.queryReturnsData(self.database, "SELECT BoardID FROM boards WHERE (BoardID=? AND OwnerID=?)", (boardid, uid))

    # Checks if a Specific Message Board has been assigned to a user
    def userOnBoard(self, uid : str, boardid : str) -> bool:
        return DBUtils.queryReturnsData(self.database, f"SELECT Board FROM {DBUtils.userdbname(uid)} WHERE Board=?", (boardid,))

    # Takes in a User's ID and a Message Board's ID and adds the Message Board to the User's Boards Table. Includes an encrypted key for the board
    def addUserToBoard(self, userid : str, boardid: str, boardkey : bytes) -> None:
        boardname = self.getBoardNameFromID(boardid)
        if not boardname:
            return
        self.database.cursor().execute(f"INSERT INTO {DBUtils.userdbname(userid)} (Board, BoardKey, BoardName) VALUES (?, ?, ?)", (boardid, boardkey, boardname))
        self.database.commit()
        self.limbLogger.registerEvent("DATA", f"User {userid} added to message board {boardid}.")

    # Registers a User's Key with its ID (Key's Hash Value)
    def registerKeyHash(self, keydata : bytes):
        uid = sha256(keydata).hexdigest()

        # Following Statement Checks if UserID is already in users table
        if DBUtils.queryReturnsData(self.database, f"SELECT UserID FROM users WHERE UserID=?", (uid,)):
            self.limbLogger.registerEvent("FAIL", f"User {uid} tried to register a user ID that already exists.")
            return b'0'
        
        self.database.cursor().execute("INSERT INTO users (UserID, PubKey) VALUES (?, ?)", (uid, keydata))
        self.database.commit()
        self.limbLogger.registerEvent("DATA", f"New User ({uid}) Inserted into Table.")
        return b'1'

    # Registers a Username Signature with its Public Key
    def registerUName(self, uid : bytes, signature : bytes, uname : str) -> bytes:
        uidstr = uid.hex()
        
        # Checks if User already has a username
        if DBUtils.queryReturnsData(self.database, f"SELECT Uname FROM users WHERE UserID='{uidstr}'"):
            self.limbLogger.registerEvent("FAIL", f"User {uidstr} already has a username.")
            return b'0'

        # Checks if User is trying to register a username that already exists
        if DBUtils.queryReturnsData(self.database, f"SELECT Uname FROM users WHERE Uname='{uname}'"):
            self.limbLogger.registerEvent("FAIL", f"User {uidstr} is trying to register a username that already exists.")
            return b'0'

        # Updates User with only Key and ID data. Adds Username and Signature
        self.database.cursor().execute("UPDATE users SET Uname= ?, UnameSignature = ? WHERE UserID = ?", (uname, signature, uidstr))
        self.createUserBoardsTable(uidstr)
        self.limbLogger.registerEvent("DATA", f"Username and Signature Set for User {uidstr}.")
        return b'1'

    # Creates a Message Board with the Given Name and Hash ID
    def registerMessageBoard(self, boardid : bytes, boardname : str, creatoruid : bytes):
        board_str = boardid.hex()
        creator_str = creatoruid.hex()

        # Returns If a Message Board with a Given ID has already been registered
        if DBUtils.queryReturnsData(self.database, f"SELECT BoardID FROM boards WHERE BoardID='{board_str}'"):
            self.limbLogger.registerEvent("FAIL", f"User {creator_str} attempted to register a message board, but the ID was already taken.")
            return b'0'
        
        # Returns If a Message Board with a Given Name has already been created 
        if DBUtils.queryReturnsData(self.database, f"SELECT Name FROM boards WHERE Name='{boardname}'"):
            self.limbLogger.registerEvent("FAIL", f"User {creator_str} attempted to register a message board, but the Name was already taken.")
            return b'0'

        # Adds the Board Data into the Boards Table
        SQL_statement = "INSERT INTO boards (BoardID, Name, OwnerID) VALUES (?, ?, ?)"
        data = (board_str, boardname, creator_str)
        self.database.cursor().execute(SQL_statement, data)
        self.database.commit()

        # Creates A Board Message Table for the current Board ID
        self.createBoardMessageTable(board_str)

        self.limbLogger.registerEvent("DATA", f"Message Board {boardname} created for user {creator_str}.")
        return b'1'

    # Invites a User to a Message Board by Adding the Board to the User's Database
    def inviteUserToBoard(self, inviterID : bytes, invitedID : bytes, boardID : bytes, boardKey : bytes):
        invitedstr = invitedID.hex()
        inviterstr = inviterID.hex()
        boardstr = boardID.hex()
        
        # Checks if User's Boards Table Exists Already
        if not DBUtils.tableExists(self.database, DBUtils.userdbname(invitedstr)):
            self.limbLogger.registerEvent("FAIL", f"User {inviterstr} attempted to invite a user that does not exist.")
            return b'0'
        
        # Checks if User Owns a Board 
        if not self.userOwnsBoard(inviterstr, boardstr):
            self.limbLogger.registerEvent("FAIL", f"User {inviterstr} attempted to invite a user to a table that they do not own.")
            return b'0'
        
        # Checks if the User is Already on the Board
        if self.userOnBoard(invitedstr, boardstr) or self.userOwnsBoard(invitedstr, boardstr):
            self.limbLogger.registerEvent("FAIL", f"User {inviterstr} attempted to invite a user that is already on the board.")
            return b'0'

        self.addUserToBoard(invitedstr, boardstr, boardKey)
        self.limbLogger.registerEvent("DATA", f"User {inviterstr} successfully invited {invitedstr} to join board {boardstr}.")
        return b'1'

    # Returns User Invite Bytes 
    def getInviteForUser(self, uid : bytes, inviteid : int):
        uidstr = uid.hex()

        if not DBUtils.tableExists(self.database, DBUtils.userdbname(uidstr)):
            self.limbLogger.registerEvent("FAIL", f"Invite requested but user {uidstr} not found.")
            return b'0'
        
        invitebytes = DBUtils.fetchSingleRecord(self.database, f"SELECT BoardKey FROM {DBUtils.userdbname(uidstr)} WHERE id=?", (inviteid,))
        
        if not invitebytes:
            self.limbLogger.registerEvent("FAIL", f"Invite requested by user {uidstr} but invite id ({inviteid}) not found.")
            return b'0'
        
        boardname = DBUtils.fetchSingleRecord(self.database, f"SELECT BoardName FROM {DBUtils.userdbname(uidstr)} WHERE id=?", (inviteid,))
        boardID = DBUtils.fetchSingleRecord(self.database, f"SELECT Board FROM {DBUtils.userdbname(uidstr)} WHERE id=?", (inviteid,))

        self.limbLogger.registerEvent("DATA", f"Invite ID {inviteid} returned for user {uidstr}.")
        return bytes.fromhex(boardID) + invitebytes + boardname.encode("ascii")
    
    # Inserts Message Data into Message Board
    def registerMessage(self, uid : bytes, boardid : bytes, messagedata : bytes):
        boardstr = boardid.hex()
        userstr = uid.hex()
        boarddb = DBUtils.boarddbname(boardstr)

        if not DBUtils.tableExists(self.database, boarddb):
            self.limbLogger.registerEvent("FAIL", "Message failed to post because board does not exist.")
            return b'0'

        if not self.userOnBoard(userstr, boardstr) and not self.userOwnsBoard(userstr, boardstr):
            self.limbLogger.registerEvent("FAIL", "Message failed to post because user lacks permission.")
            return b'0'

        self.database.cursor().execute(f"INSERT INTO {boarddb} (Sender, EncMessage, SendTime) VALUES (?, ?, ?)", (userstr, messagedata, int(time())))
        self.database.commit() 

        self.limbLogger.registerEvent("DATA", f"New message inserted by user {userstr} into table {boarddb}.")
        return b'1'

    # Gets Message Data From Message Board
    def getMessageData(self, uid : bytes, boardid : bytes, messageID : int):
        userstr = uid.hex()
        boardstr = boardid.hex()
        boarddb = DBUtils.boarddbname(boardstr)

        if not DBUtils.tableExists(self.database, boarddb):
            self.limbLogger.registerEvent("FAIL", f"Failed to get message data since board {boardstr} does not exist.")
            return b'0'

        if not self.userOnBoard(userstr, boardstr) and not self.userOwnsBoard(userstr, boardstr):
            self.limbLogger.registerEvent("FAIL", f"Failed to get message data because user {userstr} lacks permission.")
            return b'0'

        messagesender = DBUtils.fetchSingleRecord(self.database, f"SELECT Sender FROM {boarddb} WHERE id=?", (messageID,))
        if not messagesender:
            self.limbLogger.registerEvent("FAIL", f"Failed to get message data. ID not found.")
            return b'0'

        messagedata = DBUtils.fetchSingleRecord(self.database, f"SELECT EncMessage FROM {boarddb} WHERE id=?", (messageID,))
        
        messagetime = int.to_bytes(DBUtils.fetchSingleRecord(self.database, f"SELECT SendTime FROM {boarddb} WHERE id=?", (messageID,)), 8, 'big')
        return bytes.fromhex(messagesender) + messagetime + messagedata