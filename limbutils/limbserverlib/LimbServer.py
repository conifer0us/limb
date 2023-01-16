# Class that Represents the Limb Server

import toml, socket 
from limbutils.limbserverlib.LimbLogger import LimbLogger as LimbLogger
from limbutils.limbserverlib.LimbServerExceptions import *
from limbutils.limbserverlib.LimbDB import LimbDB
from limbutils.limbserverlib.PacketReader import PacketReader
from limbutils.LimbCrypto import LimbCrypto

class LimbServer:
    options = {} # Stores Options From TOML File After Loaded in init

    # The following options should always appear in the limbserver.toml file
    REQUIREDOPTIONS = ["HOST", "PORT", "DB", "LOG", "WRITELOGS", "PRINTLOGS", "PUBKEYFILE", "PRIVKEYFILE"]

    limbLogger : LimbLogger

    limbDB : LimbDB

    packetHandler : PacketReader

    limbcrypto : LimbCrypto

    # Initializes the Limb Server From a Given Configuration File
    def __init__(self, configfile : str) -> None:
        self.options = toml.load(configfile)
        try:
            self.limbLogger = LimbLogger(self.options["LOG"], self.options["WRITELOGS"], self.options["PRINTLOGS"]) 
        except:
            raise Exception("Limb cannot start without a log file chosen. Check limb.toml or log file permissions.")
        options_set = self.options.keys()
        for option in self.REQUIREDOPTIONS:
            if option not in options_set:
                raise ImproperLimbConfiguration(self.limbLogger, option)
        self.limbDB = LimbDB(self.options["DB"], self.limbLogger)
        self.limbcrypto = LimbCrypto(self.options["PRIVKEYFILE"], self.options["PUBKEYFILE"], self.limbLogger)
        self.packetHandler = PacketReader(self.limbLogger, self.limbcrypto, self.limbDB)

    # Tells the Limb Server to Start Listening from the Host and Port specified in the configuration file 
    def Start(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.options["HOST"], self.options["PORT"]))
            self.limbLogger.registerEvent("INFO", f"Server Started and Bound to {self.options['HOST']}:{self.options['PORT']}")
            while True:
                s.listen()
                conn, addr = s.accept()
                with conn:
                    data = conn.recv(4097)
                    self.limbLogger.registerEvent("CONN", f"{addr} has connected to the server. Packet Length: {len(data)}B")
                    return_data = self.packetHandler.parse_packet(data)
                    conn.send(return_data)