# The Limb Client | Connects to Limb Servers

from limbutils.limbclientlib.ClientPacketController import ClientPacketController
from limbutils.limbclientlib.InterfaceController import InterfaceController
from limbutils.LimbCrypto import LimbCrypto
import toml

CONFIGFILE = "./limbclient.toml"
REQUIREDOPTIONS = ["PUBKEYFILE", "PRIVKEYFILE"]

if __name__ == "__main__":
    interface = InterfaceController() 
    interface.showInformation("Welcome to the Linux Message Board.")
    interface.showInformation("Checking your configuration...")

    options = toml.load(CONFIGFILE)

    for option in REQUIREDOPTIONS:
        if option not in options.keys():
            interface.showInformation("Your configuration is broken. Fix your limbclient.toml and try again.")        

    socket = ClientPacketController("127.0.0.1", 6969, interface, LimbCrypto(options["PRIVKEYFILE"], options["PUBKEYFILE"]))

    while True:
        val = input("What would you like your username to be?  ")
        print("Trying to Connect to Server")
        print(socket.registerUsername(val))