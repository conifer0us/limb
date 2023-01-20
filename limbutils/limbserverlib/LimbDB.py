# A Set of Abstractions over the Limb DB

import sqlite3 as sql
from limbutils.limbserverlib.LimbLogger import LimbLogger
from hashlib import sha256
from limbutils.DBUtils import DBUtils

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
        try:
            return self.database.cursor().execute(f"SELECT PubKey FROM users WHERE Uname='{username}'").fetchall()[0][0]
        except:
            return None

    # Gets the Public Key that corresponds to the given User ID in the users database 
    def getPubKeyFromUID(self, uid : bytes) -> bytes:
        uidDigest = uid.hex()
        try:
            return self.database.cursor().execute(f"SELECT PubKey FROM users WHERE UserID='{uidDigest}'").fetchall()[0][0]
        except:
            return None

    # Gets the Name of a Board from its ID
    def getBoardNameFromID(self, boardid : str) -> str:
        try:
            return self.database.cursor().execute(f"SELECT Name FROM Boards WHERE BoardID='{boardid}'").fetchall()[0][0]
        except:
            return None

    # Gets the String Identifier of a Message Board Owner
    def userOwnsBoard(self, uid : str, boardid : str) -> bool:
        return DBUtils.queryReturnsData(self.database, f"SELECT BoardID FROM boards WHERE (BoardID='{boardid}' AND OwnerID='{uid}')")

    # Checks if a Specific Message Board has been assigned to a user
    def userOnBoard(self, uid : str, boardid : str) -> bool:
        return DBUtils.queryReturnsData(self.database, f"SELECT Board FROM {DBUtils.userdbname(uid)} WHERE Board='{boardid}'")

    # Takes in a User's ID and a Message Board's ID and adds the Message Board to the User's Boards Table. Includes an encrypted key for the board
    def addUserToBoard(self, userid : str, boardid: str, boardkey : bytes) -> None:
        boardname = self.getBoardNameFromID(boardid)
        self.database.cursor().execute(f"INSERT INTO {DBUtils.userdbname(userid)} (Board, BoardKey, BoardName) VALUES (?, ?, ?)", (boardid, boardkey, boardname))
        self.database.commit()
        self.limbLogger.registerEvent("DATA", f"User {userid} added to message board {boardid}")

    # Registers a User's Key with its ID (Key's Hash Value)
    def registerKeyHash(self, keydata : bytes) -> None:
        uid = sha256(keydata).hexdigest()
        # Following Statement Checks if UserID is already in users table
        if DBUtils.queryReturnsData(self.database, f"SELECT UserID FROM users WHERE UserID='{uid}'"):
            return
        SQL_statement = "INSERT INTO users(UserID, PubKey) VALUES (?, ?)"
        data = (uid, keydata)
        self.database.cursor().execute(SQL_statement, data)
        self.database.commit()
        self.limbLogger.registerEvent("DATA", f"New User ({uid}) Inserted into Table")

    # Registers a Username Signature with its Public Key
    def registerUName(self, uid : bytes, signature : bytes, uname : str) -> bytes:
        uidstr = uid.hex()
        
        # Checks if User already has a username
        if DBUtils.queryReturnsData(self.database, f"SELECT Uname FROM users WHERE UserID='{uidstr}'"):
            return b'Username Already Added for this User'

        # Checks if User is trying to register a username that already exists
        if DBUtils.queryReturnsData(self.database, f"SELECT Uname FROM users WHERE Uname='{uname}'"):
            return b'Username Already Taken'

        # Updates User with only Key and ID data. Adds Username and Signature
        SQL_statement = "UPDATE users SET Uname= ?, UnameSignature = ? WHERE UserID = ?"
        data = (uname, signature, uidstr)
        self.database.cursor().execute(SQL_statement, data)
        self.createUserBoardsTable(uidstr)
        self.limbLogger.registerEvent("DATA", f"Username and Signature Set for User {uidstr}")
        return b'Username Added'

    # Creates a Message Board with the Given Name and Hash ID
    def registerMessageBoard(self, boardid : bytes, boardname : str, creatoruid : bytes) -> bytes:
        board_str = boardid.hex()
        creator_str = creatoruid.hex()

        # Returns If a Message Board with a Given ID has already been registered
        if DBUtils.queryReturnsData(self.database, f"SELECT BoardID FROM boards WHERE BoardID='{board_str}'"):
            return b'A message board with this ID has already been added.'
        
        # Returns If a Message Board with a Given Name has already been created 
        if DBUtils.queryReturnsData(self.database, f"SELECT Name FROM boards WHERE Name='{boardname}'"):
            return b'A message board with that name already exists.'

        # Adds the Board Data into the Boards Table
        SQL_statement = "INSERT INTO boards (BoardID, Name, OwnerID) VALUES (?, ?, ?)"
        data = (board_str, boardname, creator_str)
        self.database.cursor().execute(SQL_statement, data)
        self.database.commit()

        # Creates A Board Message Table for the current Board ID
        self.createBoardMessageTable(board_str)

        self.limbLogger.registerEvent("DATA", f"Message Board {boardname} created for user {creator_str}")
        return b'Message Board Created'

    # Invites a User to a Message Board by Adding the Board to the User's Database
    def inviteUserToBoard(self, inviterID : bytes, invitedID : bytes, boardID : bytes, boardKey : bytes) -> bytes:
        invitedstr = invitedID.hex()
        inviterstr = inviterID.hex()
        boardstr = boardID.hex()
        if not DBUtils.tableExists(self.database, DBUtils.userdbname(invitedstr)):
            return b'That User Does Not Exist'
        if not self.userOwnsBoard(inviterstr, boardstr):
            return b'You do not have permission to access that board'
        if self.userOnBoard(invitedstr, boardstr) or self.userOwnsBoard(invitedstr, boardstr):
            return b'User already on that board'
        self.addUserToBoard(invitedstr, boardstr, boardKey)
        return b'User Added to Board'

    # Returns User Invite Bytes 
    def getInviteForUser(self, uid : bytes, inviteid : int):
        uidstr = uid.hex()
        if not DBUtils.tableExists(self.database, DBUtils.userdbname(uidstr)):
            self.limbLogger.registerEvent("FAIL", f"Invite requested but user ({uidstr}) not found.")
            return b''
        invitebytes = DBUtils.fetchSingleRecord(self.database, f"SELECT BoardKey FROM {DBUtils.userdbname(uidstr)} WHERE id=?", (inviteid,))
        if not invitebytes:
            self.limbLogger.registerEvent("FAIL", f"Invite requested but id ({inviteid}) not found.")
            return b''
        boardname = DBUtils.fetchSingleRecord(self.database, f"SELECT BoardName FROM {DBUtils.userdbname(uidstr)} WHERE id=?", (inviteid,))
        boardID = DBUtils.fetchSingleRecord(self.database, f"SELECT Board FROM {DBUtils.userdbname(uidstr)} WHERE id=?", (inviteid,))
        self.limbLogger.registerEvent("DATA", f"Invite ID {inviteid} returned for user {uidstr}")
        return bytes.fromhex(boardID) + invitebytes + boardname.encode("ascii")
    
    # Inserts Message Data into Message Board
    def registerMessage(self, uid : bytes, boardid : bytes, messagedata : bytes):
        boardstr = boardid.hex()
        userstr = uid.hex()
        boarddb = DBUtils.boarddbname(boardstr)

        if not DBUtils.tableExists(self.database, boarddb):
            self.limbLogger.registerEvent("FAIL", "Message failed to post because board does not exist.")
            return b''

        if not self.userOnBoard(userstr, boardstr) and not self.userOwnsBoard(userstr, boardstr):
            self.limbLogger.registerEvent("FAIL", "Message failed to post because user lacks permission.")
            return b''

        self.database.cursor().execute(f"INSERT INTO {boarddb} (Sender, EncMessage, SendTime) VALUES (?, ?, DATETIME())", (userstr, messagedata))
        self.database.commit() 

        self.limbLogger.registerEvent("DATA", f"New message inserted by user {userstr} into table {boarddb}.")

        return b'1'