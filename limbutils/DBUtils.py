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

    # Checks if a Given Query Returns any Data
    def queryReturnsData(dbcon : Connection, query_str : str) -> bool:
        query_results = dbcon.cursor().execute(query_str).fetchall()
        if (None,) in query_results:
            query_results.remove((None,))
        return bool(query_results)