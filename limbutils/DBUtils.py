# A Class for Shared Database Utils

from sqlite3 import Connection

class DBUtils: 
    # Returns the name for the database for a user with a certain ID
    def userdbname(name : str) -> str:
        return "user_" + name

    # Returns the name for the database for a message board with a certain ID
    def boarddbname(name : str) -> str:
        return "board_" + name

    # Checks if a Table with the Supplied Name Exists in the Limb DB
    def tableExists(dbcon : Connection, tablename : str) -> bool:
        return bool(dbcon.cursor().execute(f"""SELECT name FROM sqlite_master WHERE type='table' AND name='{tablename}';""").fetchall())