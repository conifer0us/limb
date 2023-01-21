# Class for Handling the Limb Client DB

import sqlite3 as sql 
from sqlite3 import Connection
from limbutils.DBUtils import DBUtils
from datetime import datetime

class LimbClientDB: 

    database : Connection

    # Initializes The Boards Database With Board ID, Board Name, Board Key, and Owner ID
    def createBoardsTable(self):
        if not DBUtils.tableExists(self.database, "Boards"):
            self.database.cursor().execute("CREATE TABLE Boards (id INTEGER PRIMARY KEY AUTOINCREMENT, BoardID varchar(64), BoardName varchar, BoardKey varbinary, OwnerBool int)")
            self.database.commit()

    # Initializes The Users Database with UserID and Uname
    def createUsersTable(self):
        if not DBUtils.tableExists(self.database, "Users"):
            self.database.cursor().execute("CREATE TABLE Users (UserID varchar, Uname varchar, Ukey varbinary)")
            self.database.commit()

    # Initializes A Database for a Specific Message Board, Storing Message ID, Sender Name, Message Data, and Send Time
    def createBoardMessageDB(self, boardstr):
        self.database.cursor().execute(f"CREATE TABLE {DBUtils.boarddbname(boardstr)} (id INTEGER PRIMARY KEY AUTOINCREMENT, Sender varchar(64), Message varchar, SendTime int)")
        self.database.commit()

    # Initiailzes the class with a database file to use
    def __init__(self, db_file : str) -> None:
        self.database = sql.connect(db_file)
        self.createBoardsTable()
        self.createUsersTable()

    # Adds Server Data to the Database
    def addBoardToDB(self, BoardID : bytes, BoardName : str, BoardKey : bytes, owner : bool = False):
        boardstr = BoardID.hex()

        # Checks if a Message Board with this ID has already been created
        if not DBUtils.queryReturnsData(self.database, f"SELECT BoardID from Boards where BoardID='{boardstr}'"):
            if owner:
                self.database.cursor().execute("INSERT INTO Boards (BoardID, BoardName, BoardKey, OwnerBool) VALUES (?,?,?,?)", (boardstr, BoardName, BoardKey, 1))
            else:
                self.database.cursor().execute("INSERT INTO Boards (BoardID, BoardName, BoardKey, OwnerBool) VALUES (?,?,?,?)", (boardstr, BoardName, BoardKey, 0))
            self.database.commit()
            self.createBoardMessageDB(boardstr)

    # Adds Message Data to the Database
    def addMessageToDB(self, databaseID : bytes, senderID : bytes, timestamp : int, message : str):
        senderstr = senderID.hex()
        self.database.cursor().execute(f"INSERT INTO {DBUtils.boarddbname(databaseID.hex())} (Sender, Message, SendTime) VALUES (?,?,?)", (senderstr, message, timestamp))
        self.database.commit()

    # Checks if the current user owns a board based on ID
    def ownsBoard(self, boardID : bytes):
        boardstr = boardID.hex()
        return DBUtils.queryReturnsData(self.database, "SELECT BoardID FROM Boards WHERE (OwnerBool=1 AND BoardID=?)", (boardstr,))

    # Gets Message Data From the Database
    # RETURNS: SENDER ID BYTES, MESSAGE DATA, TIMESTAMP
    def getMessageData(self, BoardID : bytes, id : int):
        boarddb = DBUtils.boarddbname(BoardID.hex())
        senderID = DBUtils.fetchSingleRecord(self.database,f"SELECT Sender FROM {boarddb} WHERE id=?", (id,))
        if not senderID:
            return None, None, None
        messagedata = DBUtils.fetchSingleRecord(self.database, f"SELECT Message FROM {boarddb} WHERE id=?", (id,))
        time = datetime.fromtimestamp(DBUtils.fetchSingleRecord(self.database, f"SELECT SendTime FROM {boarddb} WHERE id=?", id), (id,))
        return bytes.fromhex(senderID), messagedata, time

    # Gets the Latest Message ID for a certain Board ID
    def getLatestMessageID(self, BoardID : bytes) -> int:
        boardstr = BoardID.hex()
        return self.database.cursor().execute(f"SELECT COUNT (*) FROM {DBUtils.boarddbname(boardstr)}").fetchone()[0]

    # Gets the Latest Server Invite ID
    def getLatestInviteID(self) -> int:
        return self.database.cursor().execute(f"SELECT COUNT (*) FROM Boards WHERE OwnerBool=0").fetchone()[0]

    # Adds User Data to the Users Database
    def addUsersToDB(self, Uid : str, Uname : str, Ukey : bytes):
        # Checks if User with this ID has already been created
        if not DBUtils.queryReturnsData(self.database, f"SELECT UserID from Users where UserID=?", (Uid,)):
            self.database.cursor().execute("INSERT INTO Users (UserID, Uname, Ukey) VALUES (?,?,?)", (Uid, Uname, Ukey))
            self.database.commit()

    # Gets the ID of a User by a Name
    def getUserIDByName(self, uname : str) -> bytes:
        database_data = DBUtils.fetchSingleRecord(self.database, f"SELECT UserID FROM Users where Uname='{uname}'")
        if not database_data:
            return None
        else:
            return bytes.fromhex(database_data)

    # Gets Key of User by Name
    def getUserKeyByName(self, username : str) -> bytes:
        database_data = DBUtils.fetchSingleRecord(self.database, "SELECT Ukey FROM Users where Uname=?", (username,))
        if not database_data:
            return None
        else:
            return database_data

    # Gets the Username of a User by ID
    def getUserNameByID(self, userid : bytes) -> str:
        database_data = DBUtils.fetchSingleRecord(self.database, "SELECT Uname FROM Users WHERE UserID=?", (userid.hex(),))
        if not database_data:
            return None
        else:
            return database_data

    # Gets the ID of a Board from a Name
    def getBoardIDByName(self, boardname : str) -> bytes:
        database_data = DBUtils.fetchSingleRecord(self.database, "SELECT BoardID FROM Boards WHERE BoardName=?", (boardname,))
        if not database_data:
            return None
        else:
            return bytes.fromhex(database_data)
    
    # Gets the Key of a Board from a Name
    def getBoardKeyByID(self, boardID : bytes) -> bytes:
        database_data = DBUtils.fetchSingleRecord(self.database, "SELECT BoardKey FROM Boards WHERE BoardID=?", (boardID.hex(),))
        if not database_data:
            return None
        else:
            return database_data

    # Gets an Array with the Name of Every Board
    def getAllBoards(self) -> list:
        allboards = []
        boardnames = self.database.cursor().execute("SELECT BoardName FROM Boards").fetchall()
        for element in boardnames:
            allboards.append(element[0])
        return allboards