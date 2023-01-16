# A Set of Abstractions over the Limb DB

import sqlite3 as sql
from limbutils.limbserverlib.LimbLogger import LimbLogger
from hashlib import sha256

class LimbDB:
    db_file = None

    limbLogger : LimbLogger

    database : sql.Connection

    # Initializes the Limb DB with a Logger Object to Log Major Changes
    def __init__(self, db_file : str, logger : LimbLogger) -> None:
        self.limbLogger = logger
        self.database = sql.connect(db_file)
        self.limbLogger.registerEvent("DATA",f"Database file at {db_file} connected.")
        if not self.tableExists("users"):
            self.database.cursor().execute("CREATE TABLE users (UserID varchar(64) PRIMARY KEY, PubKey varbinary, Uname varchar, UnameSignature varbinary)")
            self.limbLogger.registerEvent("DATA", "No Users Table Found. Creating User Table")
            self.database.commit()

    # Registers a Given Key with its Hash Value (UserID) to Later Reference
    def registerKeyHash(self, keydata : bytes) -> None:
        uid = sha256(keydata).hexdigest()
        if not bool(self.database.cursor().execute(f"SELECT UserID FROM users WHERE UserID='{uid}'").fetchall()):
            SQL_statement = "INSERT INTO users(UserID, PubKey) VALUES (?, ?)"
            data = (uid, keydata)
            self.database.cursor().execute(SQL_statement, data)
            self.database.commit()
            self.limbLogger.registerEvent("DATA", "New User Inserted into Table")

    # Gets the Public Key that corresponds to the given User ID in the users database 
    def getPubKeyFromUID(self, uid : bytes) -> bytes:
        uidDigest = uid.hex()
        try:
            return self.database.cursor().execute(f"SELECT PubKey FROM users WHERE UserID='{uidDigest}'").fetchall()[0][0]
        except:
            return None

    # Registers a Username Signature with its Public Key
    def registerUName(self, uid : bytes, signature : bytes, uname : str) -> bytes:
        uidstr = uid.hex()
        currentUserRecord = self.database.cursor().execute(f"SELECT Uname FROM users WHERE UserID='{uidstr}'").fetchall()
        if (None,) in currentUserRecord:
            currentUserRecord.remove((None,))
        if bool(currentUserRecord):
            return b'Username Already Added for this User'
        if bool(self.database.cursor().execute(f"SELECT Uname FROM users WHERE Uname='{uname}'").fetchall()):
            return b'Username Already Taken'
        SQL = "UPDATE users SET Uname=?, UnameSignature = ? WHERE UserID = ?"
        data = (uname, signature, uidstr)
        self.database.cursor().execute(SQL, data)
        self.database.commit()
        self.limbLogger.registerEvent("DATA", f"Username and Signature Set for User {uidstr}")
        return b'Username Added'

    # Checks if a Table with the Supplied Name Exists in the Limb DB
    def tableExists(self, tablename : str) -> bool:
        return bool(self.database.cursor().execute(f"""SELECT name FROM sqlite_master WHERE type='table' AND name='{tablename}';""").fetchall())