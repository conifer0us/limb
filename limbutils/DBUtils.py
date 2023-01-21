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
    def queryReturnsData(dbcon : Connection, query_str : str, query_tuple = None) -> bool:
        try:
            if not query_tuple:
                query_results = dbcon.cursor().execute(query_str).fetchall()
            else:
                query_results = dbcon.cursor().execute(query_str, query_tuple).fetchall()
        except:
            return None
        if (None,) in query_results:
            query_results.remove((None,))
        return bool(query_results)
    
    # Fetches a Single Record from a Query if Record Exists. If not, returns None
    def fetchSingleRecord(dbcon : Connection, query_str : str, query_tuple = None):
        try:
            if not query_tuple:
                database_data = dbcon.cursor().execute(query_str).fetchall()
            else:
                database_data = dbcon.cursor().execute(query_str, query_tuple).fetchall()
        except Exception:
            return None
        if (None,) in database_data:
            database_data.remove((None,))
        if not database_data:
            return None
        else:
            return database_data[0][0]