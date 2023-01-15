# Minimalist File that Starts a Limb Server from a specified options file (OPTIONSPATH)

from limbutils.limbserverlib.LimbServer import LimbServer

OPTIONSPATH = "./limbserver.toml"

server = LimbServer(OPTIONSPATH)

server.Start()