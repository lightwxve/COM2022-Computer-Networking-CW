# Title: Festival Greeting Protocol
# File: server.py
# Author: Nilesh SUjan
# Last edit: May 8th, 2022

# Imports
import hashlib
import pickle
import socket
from datetime import date
import datetime
from time import sleep

# UDP protocol information
UDP_IP_ADDRESS = "127.0.0.1"
UDP_PORT_NO = 6789

# Whitelisted IPs to server
whitelistedIPs = ["127.0.0.1", "192.168.0.100"]

# Create a server socket using UDP
serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSock.bind((UDP_IP_ADDRESS, UDP_PORT_NO))

# Variable to keep track of last sent packet
last_packet = ""

# Dictionary to hold a festival message for each festival using key:value
festivalMessages = {
    "Eid": "Eid Mubarak!",
    "Diwali": "Happy Diwali!",
    "Christmas": "Merry Christmas!",
    "Easter": "Happy Easter!",
}

# Dictionary of dates for each festival
festivalDates = {
    "Eid": datetime.date(2022, 5, 5),
    "Diwali": datetime.date(2022, 10, 24),
    "Christmas": datetime.date(2022, 12, 25),
    "Easter": datetime.date(2022, 4, 17),
}


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


# Helper function to send packets while also timing out any packets taking too long

def sendPacket(packet, clientaddress):
    success = False  # Create a boolean variable

    while success == False:  # While the variable is false
        try:  # Try
            # Sending client the packet
            serverSock.sendto(packet, clientaddress)
            success == True  # If not exceptions then it has succeeded and the loop can break
            print("SUCCESSFULLY SENT PACKET")
            break
        except serverSock.timeout as timeout:  # If it times out
            success == False  # Set variable to false to try again
            print("PACKET TIME OUT: ", timeout)
            print("RESENDING....")
            continue

# Function to close the socket


def closeSocket():
    serverSock.close()  # Close the server socket

# Main function that gets the requested festival


def getFestival(listOfFestivalsOptedIn, clientaddress):
    # Print the festivals the client wants to be opted into
    print("The client is opted into: ", listOfFestivalsOptedIn)
    EidOpted = False  # Create a boolean variable for Eid
    DiwaliOpted = False  # Create a boolean variable for Diwali
    ChristmasOpted = False  # Create a boolean variable for Christmas
    EasterOpted = False  # Create a boolean variable for Easter

    message = ""  # Create a string variable to get all the greetings

    for i in listOfFestivalsOptedIn:  # Loop through the list of festivals
        if i == "Eid":  # If Eid is in the list then
            EidOpted = True  # Change it's boolean variable to true
            # Append the festival message of Eid to the meesage variable
            message = message + festivalMessages["Eid"] + " "
        elif i == "Diwali":  # If Diwali is in the list then
            DiwaliOpted = True  # Change it's boolean variable to true
            # Append the festival message of Diwali to the meesage variable
            message = message + festivalMessages["Diwali"] + " "
        elif i == "Christmas":  # If Christmas is in the list then
            ChristmasOpted = True  # Change it's boolean variable to true
            # Append the festival message of Christmas to the meesage variable
            message = message + festivalMessages["Christmas"] + " "
        elif i == "Easter":  # If Easter is in the list then
            EasterOpted = True  # Change it's boolean variable to true
            # Append the festival message of Easter to the meesage variable
            message = message + festivalMessages["Easter"] + " "

    print("SENDING APPROPRIATE GREETING...")

    packet = createPacket(0, 0, message)  # Create a packet with the messages
    sendPacket(packet, clientaddress)  # Send the packet

    # Proprietary server extension
    def newDay():
        currentDate = date.today()  # Get today's current date
        while (date.today() == currentDate):  # While today is today
            print("Waiting for new day...")  # Wait for a new day
            sleep(60)  # Wait every 60 seconds
        print("New day...")  # If the loop is broken then it's a new day

        if EidOpted:  # If the client is opted into Eid then
            if currentDate == festivalDates["Eid"]:  # If today is Eid
                packet = createPacket(
                    0, 0, festivalMessages["Eid"])  # Send the festival message for Eid
                sendPacket(packet, clientaddress)
        if DiwaliOpted:  # If the client is opted into Diwali then
            if currentDate == festivalDates["Diwali"]:  # If today is Diwali
                packet = createPacket(
                    0, 0, festivalMessages["Diwali"])
                # Send the festival message for Diwali
                sendPacket(packet, clientaddress)
        if ChristmasOpted:  # If the client is opted into Christmas then
            # If today is Christmas
            if currentDate == festivalDates["Christmas"]:
                packet = createPacket(0, 0, festivalMessages["Christmas"])
                # Send the festival message for Christmas
                sendPacket(packet, clientaddress)
        if EasterOpted:  # If the client is opted into Easter then
            if currentDate == festivalDates["Easter"]:  # If today is Easter
                packet = createPacket(
                    0, 0, festivalMessages["Easter"])
                # Send the festival message for Easter
                sendPacket(packet, clientaddress)

        newDay()  # Restart the function and wait for a new day

    # newDay() #Start the proprietary extension [[DISABLED FOR CONFORMANCE TESTING...]]

# Helper function to generate a checksum using the hashlib library.


def generatecheckSum(packet):
    # Takes a sequence of bytes as input and returns the 128-bit hash value as output.
    h = hashlib.new('md5')
    h.update(pickle.dumps(packet))  # Convert to byte stream

    return h.digest()  # Encode data in byte format.


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

    temporary_packet = sequence_number + acknowledgement_flag + \
        paylen_bytes + payload  # Create a temporary packet without the checksum

    # Calculate a new checksum using the temporary packet
    calculateChecksum = generatecheckSum(temporary_packet)

    if checksum == calculateChecksum:  # If both checksums are equal then the packet is not corrupt as all bytes have successfully arrived
        return False
    else:
        return True  # If there are not equal then the packet is corrupted


# Error catch function to check if a packet has been acknowledged by checking the acknowledgement flag

def checkAcknowldgement(packet):
    # Get the acknowledgement flag from the packet and convert it to integer
    acknowledgement_flag = int.from_bytes(packet[4:8], "big")

    if acknowledgement_flag == 1:  # Compare the flag to "1" which means "understood"
        return True  # Return yes meaning it was acknowledged
    else:
        return False  # Packet was not acknowledged

# Entry point into program


def start():
    while True:  # Listen to client requests
        print("SERVER RUNNING")  # Print message to show server is running
        data, addr = serverSock.recvfrom(1024)  # Receive the client data

        if addr[0] not in whitelistedIPs:  # Check if the client address is whitelisted
            print("ACCESS DENIED")
            print("Unidentified client address tried to connect to server with address: ",
                  addr[0], " on port: ", addr[1])
            fail_packet = createPacket(
                0, 1, "SERVER DENIED ACCESS")  # Create a fail packet
            print("SENDING ACCESS DENIED TO CLIENT")
            sendPacket(fail_packet, addr)  # Send the fail packet
        else:
            print("VALID CLIENT ADDRESS: ", addr)
            print("CONNECTION ESTABLISHED")

            address = addr  # Get the address
            packet = data  # Get the packet

            # First check if the packet is corrupted, if it isn't then
            if not isCorrupt(packet):
                print("REQUEST RECEIVED!")
                print("SENDING ACKNOWLEDGEMENT PACKET...")
                # Create an ack packet with ack flag as 0
                ack_packet = createPacket(
                    0, 1, "SERVER ACKNOWLEDGED THE PACKET")
                sendPacket(ack_packet, address)  # Send the ack packet
            else:
                print("ERROR... CORRUPTED PACKET. ASKING CLIENT TO RESEND...")
                # Create an ack packet with ack flag as 0
                ack_packet = createPacket(0, 0, " ")
                sendPacket(ack_packet, address)  # Send the ack packet

            # Get the payload len from the packet and convert to int
            pay_len = int.from_bytes(packet[8:12], "big")
            # Get the payload info using the payload len
            payload = packet[12:pay_len+12]
            # Decode the payload to string
            festivals = payload.decode("ascii")[:pay_len]

            # If it is a list then split the string by ,
            festivallist = [x.strip() for x in festivals.split(',')]

            getFestival(festivallist, addr)  # Get the correct greeting

        break  # Stop listening to requests
    closeSocket()  # Close the connection


start()  # Start the server
