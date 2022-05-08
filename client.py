# Title: Festival Greeting Protocol
# File: client.py
# Author: Nilesh SUjan
# Last edit: May 8th, 2022

# Imports
import hashlib
import pickle
import socket
from enum import Enum

# UDP protocol information
UDP_IP_ADDRESS = "127.0.0.1"
UDP_PORT_NO = 6789

# Create a client socket using UDP
clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Function to close the socket


def closeSocket():
    clientSock.close() # Close the client socket

# Festival enumeration for each unique festival


class Festivals(Enum):
    EID = 1
    DIWALI = 2
    CHRISTMAS = 3
    EASTER = 4

# Custom exception handling by extending the base Error class


class Error(Exception):
    """Base class for other exceptions"""
    pass

# Custom exception handling class for when the input value is too high


class ListOutOfRange(Error):
    """Raised when the input value is too much"""
    pass

# Custom exception handling class for when the user inputs something that isn't a number


class InputError(Error):
    """Raised when the input values arent numbers"""
    pass

# Custom exception handling class for when the input is not a value on the given menu


class BoundaryErr(Error):
    """Raised when the input values aren't in the list"""
    pass

# Custom exception handling class for when the user inputs two similar inputs


class DuplicateError(Error):
    """Raised when the input values are duplicated"""
    pass

# Function to check if there are duplicate entries


def checkIfDuplicates_1(listOfElems):
    ''' Check if given list contains any duplicates '''
    if len(listOfElems) == len(set(listOfElems)): # Build a set using the list to check if there are duplicates
        return False
    else:
        return True

# Function to check if the numbers the user has inputted are actually numbers


def CheckNumbersType(*numbers):
    try:
        return all(CheckNumbersType(*n) if isinstance(n, list) else [float(n)]
                   for n in numbers)
    except (ValueError, TypeError):
        return False

# Proprietary extension to allow user to opt in and opt out of certain festivals


def optIn():
    try:
        answer = list(map(str, input("""
    Please select which festivals you wish to be notified for (0-5). Separate list by ",": 
    0. Nothing
    1. Eid
    2. Diwali
    3. Christmas
    4. Easter
    """).split(",")))  # Allow user to select an option from the menu
        if len(answer) > 4:  # Check if the list of answers is bigger than 4 than it is out of range as there are only 4 options
            raise ListOutOfRange  # Raise the ListOutOfRange exception
        elif CheckNumbersType(answer) == False:  # Check if the input is number
            raise InputError  # If not raise the InputError exception
        elif all(int(i) >= 5 for i in answer):  # Check if any number is bigger than 5
            raise BoundaryErr  # If they are then raise the BoundaryErr exception as the highest number they can choose is 4
        # Check if there are duplicates inputs
        elif checkIfDuplicates_1(answer):
            raise DuplicateError  # If there are then raise the DuplicateError exception
    except ListOutOfRange:  # Raise the error
        print("You've inputted too many numbers, try again")
        optIn()  # Let user try again
    except InputError:  # Raise the error
        print("Not all inputs are numbers, try again")
        optIn()  # Let user try again
    except BoundaryErr:  # Raise the error
        print("Input number not on list, try again")
        optIn()  # Let user try again
    except DuplicateError:  # Raise the error
        print("Input numbers are duplicated, try again")
        optIn()  # Let user try again
    listOfFestivals = []  # Create an empty list of festivals
    for i in answer:  # Loop through the user's answer
        if i == "1":  # If user has selected 1
            listOfFestivals.append("Eid")  # Put Eid in the festival list
        elif i == "2":  # If user has selected 2
            listOfFestivals.append("Diwali")  # Put Diwali in the festival list
        elif i == "3":  # If user has selected 3
            # Put Christmas in the festival list
            listOfFestivals.append("Christmas")
        elif i == "4":  # If user has selected 4
            listOfFestivals.append("Easter")  # Put Easter in the festival list

    # Display the festivals the user has selected
    print("Selected festivals: ", listOfFestivals)

    return listOfFestivals  # Return the list of festivals

# Helper function to send packets while also timing out any packets taking too long


def sendPacket(packet, clientaddress):
    success = False #Create a boolean variable

    while success == False: #While the variable is false
        try: #Try
            clientSock.sendto(packet, clientaddress) #Sending client the packet
            success == True #If not exceptions then it has succeeded and the loop can break
            break
        except clientSock.timeout as timeout: #If it times out
            success == False #Set variable to false to try again
            print("PACKET TIME OUT: ", timeout)
            print("RESENDING....")
            continue

# Helper function to generate a checksum using the hashlib library.


def generatecheckSum(packet):
    h = hashlib.new('md5') #Takes a sequence of bytes as input and returns the 128-bit hash value as output.
    h.update(pickle.dumps(packet)) #Convert to byte stream

    return h.digest() #Encode data in byte format.

# Function to create a packet given the correct paramaters


def createPacket(sequence_number, acknowledgement_flag, payload):
    # As specified in the RFC, the sequence number is 0 plus the length of the payload
    sequence_number = 0 + len(payload)
    acknowledgement_flag = acknowledgement_flag  # Ack flag
    payload = payload  # Payload

    if type(payload) == list:  # Check if the payload is a list incase there are multiple festivals the user is opted into
        separator = ", "  # If it is then seperate the list by ","
        # Join the items in the list together to create a string
        payload = separator.join(payload)

    # Encode the payload length ASCII
    payload_length = len(payload.encode("ascii"))
    payload = payload.encode("ascii")  # Encode the payload using ASCII

    # Convert the sequence number to bytes with byteorder big
    sequence_number = sequence_number.to_bytes(4, byteorder="big")
    # Convert the acknowledgement_flag to bytes with byteorder big
    acknowledgement_flag = acknowledgement_flag.to_bytes(4, byteorder="big")
    # Convert the payload_length to bytes with byteorder big
    payload_length = payload_length.to_bytes(4, byteorder="big")

    temporary_packet = sequence_number + acknowledgement_flag + payload_length + \
        payload  # Create a temporary packet with the above information
    # Calculate the checksum using the temporary packet
    checksum_num = generatecheckSum(temporary_packet)

    packet = sequence_number + acknowledgement_flag + payload_length + payload + \
        checksum_num  # Create the final packet by concatentating all other bytes

    return packet  # Return the packet

# Function to check if the packet is corrupted

def isCorrupt(packet):
    # Unpack the first 4 bytes which should be the sequence number as specified by the RFC
    sequence_number = packet[0:4]
    # Unpack bytes from 4-8 which should be the acknowledgement_flag as specified by the RFC
    acknowledgement_flag = packet[4:8]
    # Unpack bytes from 8-12 which should be the payload_length as specified by the RFC
    paylen_bytes = packet[8:12]
    # Convert the payload length currrently in bytes to integer
    payload_length = int.from_bytes(paylen_bytes, byteorder='big')
    # Unpack bytes from 12 - payload length +12 which should be the payload as specified by the RFC
    payload = packet[12:payload_length+12]
    # Unpack bytes from payload_length+12 which should be the check_sum as specified by the RFC
    checksum = packet[payload_length+12:]

    temporary_packet = sequence_number + acknowledgement_flag + paylen_bytes + payload  # Create a temporary packet without the checksum

    # Calculate a new checksum using the temporary packet
    calculateChecksum = generatecheckSum(temporary_packet)

    if checksum == calculateChecksum:  # If both checksums are equal then the packet is not corrupt as all bytes have successfully arrived
        return False
    else:
        return True  # If there are not equal then the packet is corrupted

# Error catch function to check if a packet has been acknowledged by checking the acknowledgement flag


def checkAcknowldgement(packet):
    acknowledgement_flag = int.from_bytes(packet[4:8], "big") # Get the acknowledgement flag from the packet and convert it to integer

    if acknowledgement_flag == 1: # Compare the flag to "1" which means "understood"
        return True # Return yes meaning it was acknowledged
    else:
        return False # Packet was not acknowledged


# Main entry point of the program
def main():
    festivals = optIn()  # Get the list of festivals the user wants
    # Crete a UDP packet with the payload as the festivals
    UDPPacket = createPacket(0, 0, festivals)
    # Send the payload to the server
    sendPacket(UDPPacket, (UDP_IP_ADDRESS, UDP_PORT_NO))
    print('WAITING FOR ACK....')  # Wait for acknowledgement


main()  # Run the main function

# Listen for the server's response
while True:

    acknowledgement_packet = clientSock.recv(
        1024)  # Receieve the acknowledgement packet

    if isCorrupt(acknowledgement_packet):  # Check if the packet is corrupted
        print("PACKET RECEIVED WAS CORRUPTED...")
        print("RESTARTING...")
        main() # Restart the protocol from the top
    # Check if packet was acknowledged
    elif not checkAcknowldgement(acknowledgement_packet):
        print("PACKET WAS NOT ACKNOWLEDGED")
        print("RESTARTING...")
        main() # Restart the protocol from the top
    else:
        print("ACKNOWLEDGED PACKET")

    greeting_packet = clientSock.recv(
        2048)  # Receieve the greeting packet

    if isCorrupt(greeting_packet):  # Check if the packet is corrupted
        print("PACKET RECEIVED WAS CORRUPTED....")
        print("RESTARTING...")
        main() # Restart the protocol from the top
    else:
        print("PACKET RECEIVED SUCCESSFULLY")
        # Get the payload length and convert it from bytes to int to get the payload
        pay_len = int.from_bytes(greeting_packet[8:12], "big")
        # Get the payload using the payload length
        payload = greeting_packet[12:pay_len+12]

        print("MESSAGE FROM SERVER: ", payload.decode("ascii")
              [:pay_len])  # Print the message from the server
        break  # Stop listening to requests

closeSocket()  # Close the connection
