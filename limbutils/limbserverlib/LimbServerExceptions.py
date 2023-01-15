# Contains Classes for Handling Errors that Can be Encountered when Dealing with the Limb Server

from limbutils.limbserverlib.LimbLogger import LimbLogger as logger

# Exception that Says a Key is Improper
class ImproperLimbConfiguration(Exception):
    def __init__(self, limbLogger : logger, ImproperKeyName):
        loglabel = "Error"
        logmessage = f"The Following Key is not Set or is Improperly Set in your Configuration: {ImproperKeyName}"
        limbLogger.registerEvent(loglabel, logmessage)
        super().__init__(f"{loglabel} {logmessage}")