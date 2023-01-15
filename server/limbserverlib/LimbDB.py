# A Set of Abstractions over the Limb DB

import sqlite3 as sql
from limbserverlib.LimbLogger import LimbLogger

class LimbDB:
    db_file = None

    limbLogger : LimbLogger

    database : sql.Cursor

    def __init__(self, db_file, logger : LimbLogger):
        self.limbLogger = logger
        self.database = sql.connect(db_file).cursor() 
        self.limbLogger.registerEvent("INFO",f"Database file at {db_file} connected.")

    def tableExists(self, tablename):
        return bool(self.database.execute(f"""SELECT name FROM sqlite_master WHERE type='table' AND name='{tablename}';""").fetchall())