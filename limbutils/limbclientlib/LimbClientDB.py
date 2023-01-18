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
            self.database.cursor().execute("CREATE TABLE Boards (BoardID varchar(64), BoardName varchar, BoardKey varbinary, OwnerID varchar(64))")
            self.database.commit()

    # Initializes The Users Database with UserID and Uname
    def createUsersTable(self):
        if not DBUtils.tableExists(self.database, "Users"):
            self.database.cursor().execute("CREATE TABLE Users (UserID varchar(64), Uname varchar)")
            self.database.commit()

    # Initializes A Database for a Specific Message Board, Storing Message ID, Sender Name, Message Data, and Send Time
    def createBoardMessageDB(self, boardstr):
        self.database.cursor().execute(f"CREATE TABLE {DBUtils.boarddbname(boardstr)} (id INTEGER PRIMARY KEY AUTOINCREMENT, Sender varchar(64), Message varchar, SendTime datetime)")

    # Initiailzes the class with a database file to use
    def __init__(self, db_file : str) -> None:
        self.database = sql.connect(db_file)
        self.createBoardsTable()
        self.createUsersTable()

    # Adds Server Data to the Database
    def addBoardToDB(self, BoardID : bytes, BoardName : str, BoardKey : bytes, OwnerID : bytes):
        boardstr = BoardID.hex()
        ownerstr = OwnerID.hex()

        # Checks if a Message Board with this ID has already been created
        if DBUtils.queryReturnsData(self.database, f"SELECT BoardID from Boards where BoardID='{boardstr}'"):
            self.database.cursor().execute("INSERT INTO Boards (BoardID, BoardName, BoardKey, OwnerID) VALUES (?,?,?,?)", (boardstr, BoardName, BoardKey, ownerstr))
            self.database.commit()
            self.createBoardMessageDB(boardstr)