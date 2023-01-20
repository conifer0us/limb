# Class for Handling the Limb Client DB

import sqlite3 as sql 
from sqlite3 import Connection
from limbutils.DBUtils import DBUtils
from hashlib import sha256

class LimbClientDB: 

    database : Connection

    # Initializes The Boards Database With Board ID, Board Name, Board Key, and Owner ID
    def createBoardsTable(self):
        if not DBUtils.tableExists(self.database, "Boards"):
            self.database.cursor().execute("CREATE TABLE Boards (BoardID varchar(64), BoardName varchar, BoardKey varbinary)")
            self.database.commit()

    # Initializes The Users Database with UserID and Uname
    def createUsersTable(self):
        if not DBUtils.tableExists(self.database, "Users"):
            self.database.cursor().execute("CREATE TABLE Users (UserID varchar(64), Uname varchar, Ukey varbinary)")
            self.database.commit()

    # Initializes A Database for a Specific Message Board, Storing Message ID, Sender Name, Message Data, and Send Time
    def createBoardMessageDB(self, boardstr):
        self.database.cursor().execute(f"CREATE TABLE {DBUtils.boarddbname(boardstr)} (id INTEGER PRIMARY KEY AUTOINCREMENT, Sender varchar(64), Message varchar, SendTime datetime)")
        self.database.commit()

    # Initiailzes the class with a database file to use
    def __init__(self, db_file : str) -> None:
        self.database = sql.connect(db_file)
        self.createBoardsTable()
        self.createUsersTable()

    # Adds Server Data to the Database
    def addBoardToDB(self, BoardID : bytes, BoardName : str, BoardKey : bytes):
        boardstr = BoardID.hex()

        # Checks if a Message Board with this ID has already been created
        if not DBUtils.queryReturnsData(self.database, f"SELECT BoardID from Boards where BoardID='{boardstr}'"):
            self.database.cursor().execute("INSERT INTO Boards (BoardID, BoardName, BoardKey) VALUES (?,?,?)", (boardstr, BoardName, BoardKey))
            self.database.commit()
            self.createBoardMessageDB(boardstr)

    # Adds User Data to the Users Database
    def addUsersToDB(self, Uid : str, Uname : str, Ukey : bytes):
        # Checks if User with this ID has already been created
        if not DBUtils.queryReturnsData(self.database, f"SELECT UserID from Users where UserID='{Uid}'"):
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