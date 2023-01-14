# Minimalist File that Starts a Limb Server from a specified options file (OPTIONSPATH)

from limbserverlib.LimbServer import LimbServer

OPTIONSPATH = "./limb.toml"

server = LimbServer(OPTIONSPATH)

server.Start()