# Class for Reading Packets coming into the Server. Understands Message Types and Handles Them.

from limbserverlib.LimbLogger import LimbLogger
from limbserverlib.LimbCrypto import LimbCrypto

class PacketReader:
    # The Following Array Defines the Functions That Handle Certain Types of Packets

    logger : LimbLogger

    cryptography : LimbCrypto

    packet_function_mapping = {} 

    def __init__(self, logger : LimbLogger, crypto : LimbCrypto) -> None:
        self.logger = logger
        self.cryptography = crypto
        # Defines what Functions the Server Should Call When it Receives a Packet Based on the First Byte of the Packet
        self.packet_function_mapping = { 
            1 : self.pubkey_welcome
        }

    def parse_packet(self, bytearray):
        packetMode = int(bytearray[0])
        try:
            return self.packet_function_mapping[packetMode](bytearray)
        except KeyError:
            self.logger.registerEvent("FAIL", f"Attempted Connection Did not Contain Proper Packet Type.")
            return bytes("Connection Did not Contain Proper Packet Type.", "utf-8")

    def pubkey_welcome(self, bytearray):
        self.logger.registerEvent("EST", f"Establish Packet Received From Public Key {str(bytearray[1:])}. Response sent. Connection Closed.")
        return bytes("Public Key", 'utf-8')