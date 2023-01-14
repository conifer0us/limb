# Class that Represents the Limb Server

import toml, socket 
from limbserverlib.LimbLogger import LimbLogger as LimbLogger
from limbserverlib.LimbServerExceptions import *
from limbserverlib.LimbDB import LimbDB

class LimbServer:
    # Server Options After Loaded from toml Should Always Contain HOST, PORT, DB, and LOG
    options = {}

    REQUIREDOPTIONS = ["HOST", "PORT", "DB", "LOG"]

    limbLogger : LimbLogger

    limbDB : LimbDB

    def __init__(self, configfile):
        self.options = toml.load(configfile)
        try:
            self.limbLogger = LimbLogger(self.options["LOG"]) 
        except:
            raise Exception("Limb cannot start without a log file chosen. Check limb.toml or log file permissions.")
        options_set = self.options.keys()
        for option in self.REQUIREDOPTIONS:
            if option not in options_set:
                raise ImproperLimbConfiguration(self.limbLogger, option)
        self.limbDB = LimbDB(self.options["DB"], self.limbLogger)

    def Start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.options["HOST"], self.options["PORT"]))
            self.limbLogger.registerEvent("INFO", f"Server Started and Bound to {self.options['HOST']}:{self.options['PORT']}")
            while True:
                s.listen()
                conn, addr = s.accept()
                with conn:
                    print(f"{addr} has connected to the server.")
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        conn.sendall(data)