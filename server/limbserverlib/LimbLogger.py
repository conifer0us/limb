# Class that Handles Logging Limb Events

from datetime import datetime

class LimbLogger:
    def __init__(self, fileName) -> None:
        self.logFile = open(fileName, "a")

    # Registers Errors and Events in the Supplied Log File
    def registerEvent(self, label : str, message : str, logTime = True):
        message_str = f"{label}  |  {message}\n"
        if logTime:
            message_str = f'[{datetime.now().strftime("%d/%m/%Y %H:%M:%S")}]  ' + message_str
        self.logFile.write(message_str)
        self.logFile.flush()