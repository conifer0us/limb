# A Set of Abstractions over the Limb DB

import sqlite3 as sql
from limbutils.limbserverlib.LimbLogger import LimbLogger

class LimbDB:
    db_file = None

    limbLogger : LimbLogger

    database : sql.Cursor

    # Initializes the Limb DB with a Logger Object to Log Major Changes
    def __init__(self, db_file : str, logger : LimbLogger) -> None:
        self.limbLogger = logger
        self.database = sql.connect(db_file).cursor() 
        self.limbLogger.registerEvent("INFO",f"Database file at {db_file} connected.")

    # Registers a Given Key with its Hash Value to Reference Later
    def registerKey(self, keydata : bytes) -> None:
        pass

    # Checks if a Table with the Supplied Name Exists in the Limb DB
    def tableExists(self, tablename : str) -> bool:
        return bool(self.database.execute(f"""SELECT name FROM sqlite_master WHERE type='table' AND name='{tablename}';""").fetchall())