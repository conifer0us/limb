# Class that Handles Logging Limb Events

from datetime import datetime

class LimbLogger:
    printlogs : bool
    writelogs : bool

    def __init__(self, fileName, writelogs : bool, printlogs : bool) -> None:
        self.logFile = open(fileName, "a")
        self.writelogs = writelogs
        self.printlogs = printlogs

    # Registers Errors and Events in the Supplied Log File
    def registerEvent(self, label : str, message : str, logTime = True):
        message_str = f"{label}  |  {message}\n"
        if logTime:
            message_str = f'[{datetime.now().strftime("%d/%m/%Y %H:%M:%S")}]  ' + message_str
        if self.printlogs:
            print(message_str)
        if self.writelogs:
            self.logFile.write(message_str)
            self.logFile.flush()