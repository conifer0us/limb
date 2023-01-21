# The Limb Client | Connects to Limb Servers

from limbutils.limbclientlib.LimbServerAPI import LimbServerAPI
from limbutils.LimbCrypto import LimbCrypto
from limbutils.limbclientlib.LimbClientDB import LimbClientDB
import toml
from curses import wrapper
import time
import curses
from art import text2art

api : LimbServerAPI

CONFIGFILE = "./limbclient.toml"
REQUIREDOPTIONS = ["PUBKEYFILE", "PRIVKEYFILE", "DB", "HOST", "PORT"]

currentboard = ""

# Returns Fancy Blocked Text As a String
def fancyText(inputstr : str) -> str:
    return text2art(inputstr)

def displayMainPage(stdscr):
    # Sets up curses and Displays a Generic Message
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.clear()
    stdscr.addstr(fancyText("LIMB"))
    stdscr.addstr("Ready to Connect? (y/n)")
    stdscr.refresh()

    # Reads Yes or No Key for Connection
    while True:
        key = stdscr.getkey()
        if key == 'y' or key == "Y":
            if api.isUsernameRegistered():
                return 3
            else:
                return 2
        elif key == 'n' or key == 'N':
            exit()

# Displays a Username Select Page
def displayUsernameSelectPage(stdscr):
    # Sets up the Screen and Prompts for Username
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.clear()
    stdscr.addstr(fancyText("LIMB"))
    stdscr.addstr("Please Enter your Limb Username.\nUsernames have to be ASCII strings with 8 characters or less.")

    # Repests until a Valid Username is found
    while True:
        # Get Username String Input
        stdscr.addstr("\nEnter A Username: ")
        curses.curs_set(1)
        curses.echo()
        unameinput = stdscr.getstr().decode('ascii')
        curses.noecho()
        curses.curs_set(0)

        # Switch to Dashboard if Username Accepted
        if api.registerUsername(unameinput):
            return 3

        # Provide User with Error if Username Incorrect
        stdscr.clear() 
        stdscr.addstr(fancyText("LIMB"))
        stdscr.addstr("Your username: " + unameinput + " was not accepted. It may have been registered already.")
        stdscr.refresh()

# Display the Message Boards a User is In
def displayBoardsPage(stdscr):
    # Sets up the Page 
    curses.curs_set(0)
    global currentboard
    stdscr.nodelay(False)

    # Loads All Boards from The Server and local Database
    api.loadInvites()
    boardid = 0
    boardlist = api.getBoards()
    boardnum = len(boardlist)

    # Endlessly regenerates the screen as different options are selected
    while True:
        # Screen Generated with Welcome Message
        stdscr.clear()
        stdscr.addstr(fancyText("LIMB"))
        stdscr.addstr(f"Hi, {api.getUname(api.clientID)}! Welcome to your Limb Dashboard!\n")
        
        # Displays Options for User Depending on How Many Boards There Are and Whether the User is the Owner of the Current One
        isowner = False
        if boardnum == 0:
            stdscr.addstr("\nNo Boards Here Now... Create One or Check Back Later\n\n")
        else:
            stdscr.addstr(f"\nBoard {boardid + 1} of {boardnum}: {boardlist[boardid]}\n\n")
            isowner = api.ownsBoard(boardlist[boardid])
            stdscr.addstr("Press F to hop on the board.\n")
        if boardnum > 1:
            stdscr.addstr("Press A/D to Scroll Through Boards\n")
        stdscr.addstr("Press C to Create a New Message Board.\n")
        if isowner:
            stdscr.addstr("Press I to Invite People to the Board.\n")
        stdscr.refresh()

        # Processes Keypresses based on previous instructions
        while True:
            key = stdscr.getkey()
            
            # C returns to Create Message Board
            if key == "c" or key == "C":
                return 5

            # I returns to Invitation Board
            elif (key == "i" or key == "I") and isowner:
                currentboard = boardlist[boardid]
                return 6

            # A Scrolls Left if Not on the First Board
            elif key == 'a' or key == 'A':
                if boardid == 0:
                    continue
                else:
                    boardid -= 1
                    break

            # D Scrolls Right if Not on the Last Board
            elif key == 'd' or key == 'D':
                if boardid >= boardnum - 1:
                    continue
                else:
                    boardid += 1
                    break

            # F Selects the Board and Pushes User to The Interaction Screen
            elif key == 'f' or key == 'F':
                currentboard = boardlist[boardid]
                return 4

# Allows a User to Interact with a Message Board
def displayMessageBoard(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.clear()
    stdscr.addstr(f"Now in Board {currentboard}.")
    stdscr.refresh()
    while True:
        time.sleep(5)

# Allows a User to Create Message Boards
def displayCreateMessageBoard(stdscr):
    # Sets up the Screen
    
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.clear()
    stdscr.addstr(fancyText("LIMB"))
    stdscr.addstr("Create A Message Board? (y/n) \n")
    
    # Confirms Choice to Create Board
    while True:
        key = stdscr.getkey()
        if key == 'y' or key == "Y":
            break
        elif key == 'n' or key == 'N':
            return 3
    stdscr.addstr("Board Names are No More Than 8 ASCII Characters\n")
    
    # Loops Until Valid Board has been Created
    while True:
        stdscr.addstr("What would you like to call your board? ")
        stdscr.refresh()

        # Gets Board Name as String Input
        curses.curs_set(1)
        curses.echo()
        boardname = stdscr.getstr().decode('ascii')
        curses.noecho()
        curses.curs_set(0)

        # Attempts to Register Board and checks whether the Server Accepted It
        boardregistration = api.registerNewMessageBoard(boardname)

        # Displays Message If Server Accepts Board. Waits for user to acknowledge message with b, then exits to dashboard
        if boardregistration:
            stdscr.addstr(f"Your board {boardname} has been registered.\nPress b to return to your boardlist.\n")
            stdscr.refresh()
            while True:
                key = stdscr.getkey()
                if key == "b" or key == "B":
                    return 3

        # Displays error message and loops if not valid board
        else:
            stdscr.clear()
            stdscr.addstr(f"Your board {boardname} failed to register.\nUsing a different or compatible name could help.\n")
            continue

# Allows a User to Invite Others to their Message Boards
def displayInvitePeopletoBoard(stdscr):
    # Sets up the Screen and Prompts to be sure about invitation
    stdscr.nodelay(False)
    curses.curs_set(0)
    stdscr.clear()
    stdscr.addstr(fancyText("LIMB"))
    stdscr.addstr(f"Hi, {api.getUname(api.clientID)}! Welcome to your Limb Dashboard!\n")
    stdscr.addstr("Invite someone to the board? (y/n) \n")
    stdscr.refresh()
    
    # Reads input to See if User Confirms Invitation Choice
    while True:
        key = stdscr.getkey()
        if key == 'y' or key == "Y":
            break
        elif key == 'n' or key == 'N':
            return 3
    
    # Loops Infinitely Until Invitation is Confirmed
    while True:
        # Gets User Input for Invitation Choice
        stdscr.addstr("Who would you like to invite? ")
        stdscr.refresh() 
        curses.curs_set(1)
        curses.echo()
        otheruser = stdscr.getstr().decode('ascii')
        curses.noecho()
        curses.curs_set(0)

        # Checks if Server Accepted Invitation; Puts out Confirmation Message and Prompts User to Acknowledge it Before Returning to Dashboard
        invitationbool = api.inviteUserToBoard(otheruser, currentboard)
        if invitationbool:
            stdscr.addstr(f"Your invitation has been sent.\nPress b to return to your boardlist.\n")
            stdscr.refresh()
            while True:
                key = stdscr.getkey()
                if key == "b" or key == "B":
                    return 3

        # Loops and Displays Error Message if Invitation not Accepted
        else:
            stdscr.clear()
            stdscr.addstr(f"Your invitation failed to send.\nThe user you selected likely does not exist.\n")
            continue


# Main Program Loop, starts in one menu function and then continues to other pages depending on function return values
def main(stdscr):
    screen_id_to_function = {
        1 : displayMainPage,
        2 : displayUsernameSelectPage, 
        3 : displayBoardsPage, 
        4 : displayMessageBoard, 
        5 : displayCreateMessageBoard,
        6 : displayInvitePeopletoBoard
    }
    currentscreen = 1
    while True:
        currentscreen = screen_id_to_function[currentscreen](stdscr)
        
# Loads Configuration and Prints Error if wrong. Starts main method and the client behind the curses wrapper.
if __name__ == "__main__":
    options = toml.load(CONFIGFILE)
    for option in REQUIREDOPTIONS:
        if option not in options.keys():
            print("Your configuration is broken. Fix your limbclient.toml and try again.")

    database = LimbClientDB(options["DB"])

    api = LimbServerAPI(options["HOST"], options["PORT"], LimbCrypto(options["PRIVKEYFILE"], options["PUBKEYFILE"]), database)

    wrapper(main)