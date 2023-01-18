# Class for Handling the Limb Client DB

import sqlite3 as sql 
from sqlite3 import Connection
from limbutils.DBUtils import DBUtils
from hashlib import sha256

class LimbClientDB: 

    database : Connection

    # Initiailzes the class with a database file to use
    def __init__(self, db_file : str) -> None:
        self.database = sql.connect(db_file)
        if not DBUtils.tableExists(self.database, "Boards"):
            self.database.cursor().execute("CREATE TABLE Boards (BoardID varchar(64), BoardName varchar, BoardKey varbinary, OwnerID varchar(64))")
            self.database.commit()
        if not DBUtils.tableExists(self.database, "Users"):
            self.database.cursor().execute("CREATE TABLE Users (UserID varchar(64), Uname varchar)")

    # Adds Server Data to the Database
    def addServerToDB(self, BoardID : bytes, BoardName : str, BoardKey : bytes, OwnerID : bytes):
        boardstr = BoardID.hex()
        ownerstr = OwnerID.hex()
        self.database.cursor().execute("INSERT INTO Boards (BoardID, BoardName, BoardKey, OwnerID) VALUES (?,?,?,?)", (boardstr, BoardName, BoardKey, ownerstr))
        self.database.cursor().execute(f"CREATE TABLE {DBUtils.boarddbname(boardstr)} (id INTEGER PRIMARY KEY AUTOINCREMENT, Sender varchar(64), EncMessage varbinary, SendTime datetime)")
        self.database.commit()