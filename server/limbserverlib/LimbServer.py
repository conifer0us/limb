# Class that Represents the Limb Server

import toml, socket 
from limbserverlib.LimbLogger import LimbLogger as LimbLogger
from limbserverlib.LimbServerExceptions import *
from limbserverlib.LimbDB import LimbDB
from limbserverlib.PacketReader import PacketReader
from limbserverlib.LimbCrypto import LimbCrypto
import base64

class LimbServer:
    # Server Options After Loaded from toml Should Always Contain HOST, PORT, DB, and LOG
    options = {}

    REQUIREDOPTIONS = ["HOST", "PORT", "DB", "LOG", "PUBKEYFILE", "PRIVKEYFILE"]

    limbLogger : LimbLogger

    limbDB : LimbDB

    packetHandler : PacketReader

    limbcrypto : LimbCrypto

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
        self.limbcrypto = LimbCrypto(self.limbLogger, self.options["PRIVKEYFILE"], self.options["PUBKEYFILE"])
        self.packetHandler = PacketReader(self.limbLogger, self.limbcrypto)
        message = bytes("Test Message Please Ignore", 'utf-8')

    def Start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.options["HOST"], self.options["PORT"]))
            self.limbLogger.registerEvent("INFO", f"Server Started and Bound to {self.options['HOST']}:{self.options['PORT']}")
            while True:
                s.listen()
                conn, addr = s.accept()
                with conn:
                    data = conn.recv(4096)
                    self.limbLogger.registerEvent("CONN", f"{addr} has connected to the server. Packet Length: {len(data)}")
                    return_data = self.packetHandler.parse_packet(data)
                    conn.send(return_data)