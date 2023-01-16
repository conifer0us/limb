# Class for Checking Whether Usernames are Properly Formatted

class UsernameFormat:
    
    UNAMECHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"

    def is_properly_formatted(username : str) -> bool:
        if len(username) == 0 or len(username) > 8:
            return False
        for x in username:
            if x not in UsernameFormat.UNAMECHARSET:
                return False
        return True