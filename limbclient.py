# The Limb Client | Connects to Limb Servers

from limbutils.limbclientlib.LimbServerAPI import LimbServerAPI
from limbutils.limbclientlib.InterfaceController import InterfaceController
from limbutils.LimbCrypto import LimbCrypto
from limbutils.limbclientlib.LimbClientDB import LimbClientDB
import toml
from hashlib import sha256

CONFIGFILE = "./limbclient.toml"
REQUIREDOPTIONS = ["PUBKEYFILE", "PRIVKEYFILE", "DB"]

if __name__ == "__main__":
    interface = InterfaceController() 
    interface.showInformation("Welcome to the Linux Message Board.")
    interface.showInformation("Checking your configuration...")

    options = toml.load(CONFIGFILE)

    for option in REQUIREDOPTIONS:
        if option not in options.keys():
            interface.showInformation("Your configuration is broken. Fix your limbclient.toml and try again.")        

    database = LimbClientDB(options["DB"])

    limbserver = LimbServerAPI("127.0.0.1", 6969, interface, LimbCrypto(options["PRIVKEYFILE"], options["PUBKEYFILE"]), database)

    limbserver.getMessage("hell2", 1)

    limbserver.registerUsername(input("What username would you like? "))
    limbserver.registerNewMessageBoard(input("What would you like to name your board? "))

    while True:
        boardname = input("What board would you like to post to? ")
        message = input("What would you like to post? ")
        print(limbserver.postMessage(message, boardname))
