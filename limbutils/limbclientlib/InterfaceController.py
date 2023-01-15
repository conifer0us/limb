# Class for Handling The Limb Client Interface

class InterfaceController:
    
    def __init__(self) -> None:
        pass

    # Prints a Simple Information Message to the Client Terminal
    def showInformation(self, message : str) -> None:
        print(f"INFO | {message}")