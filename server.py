import hashlib
import pickle
import socket
from datetime import date
import datetime
from time import sleep

UDP_IP_ADDRESS = "127.0.0.1"
UDP_PORT_NO = 6789

whitelistedIPs = ["127.0.0.1"]

serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

serverSock.bind((UDP_IP_ADDRESS, UDP_PORT_NO))

last_packet = ""

festivalMessages = {
    "Eid": "Eid Mubarak!",
    "Diwali": "Happy Diwali!",
    "Christmas": "Merry Christmas!",
    "Easter": "Happy Easter!",
}

festivalDates = {
    "Eid": datetime.date(2022, 5, 5),
    "Diwali": datetime.date(2022, 10, 24),
    "Christmas": datetime.date(2022, 12, 25),
    "Easter": datetime.date(2022, 4, 17),
}


def createPacket(seq, ack, pay_load):
    pay_len = len(pay_load)
    seq_num = seq + pay_len
    ack_flag = ack
    payload = pay_load
    pay_len = len(payload.encode("ascii"))

    payload = payload.encode("ascii")

    seq_num = seq_num.to_bytes(4, byteorder="big")
    ack_flag = ack_flag.to_bytes(4, byteorder="big")
    pay_len = pay_len.to_bytes(4, byteorder="big")

    pkt_no_checksum = seq_num + ack_flag + pay_len + payload
    checksum_num = checksum(pkt_no_checksum)

    pkt = seq_num + ack_flag + pay_len + payload + checksum_num

    return pkt


def sendPacket(packet, clientaddress):
    success = False

    while success == False:
        try:
            serverSock.sendto(packet, clientaddress)
            success == True
            break
        except serverSock.timeout as inst:
            success == False
            print("PACKET TIMED OUT")
            print("RESENDING....")
            continue


def closeSocket():
    serverSock.close()


def main(listOfFestivalsOptedIn, clientaddress):
    print("The client is opted into: ", listOfFestivalsOptedIn)
    EidOpted = False
    DiwaliOpted = False
    ChristmasOpted = False
    EasterOpted = False

    message = ""

    for i in listOfFestivalsOptedIn:
        if i == "Eid":
            EidOpted = True
            message = message + festivalMessages["Eid"] + " "
        elif i == "Diwali":
            DiwaliOpted = True
            message = message + festivalMessages["Diwali"] + " "
        elif i == "Christmas":
            ChristmasOpted = True
            message = message + festivalMessages["Christmas"] + " "
        elif i == "Easter":
            EasterOpted = True
            message = message + festivalMessages["Easter"] + " "

    packet = createPacket(0, 0, message)
    sendPacket(packet, clientaddress)

    def newDay():
        currentDate = date.today()
        while (date.today() == currentDate):
            print("Waiting for new day...")
            sleep(60)
        print("New day...")

        if EidOpted:
            if currentDate == festivalDates["Eid"]:
                packet = createPacket(
                    0, 0, festivalMessages["Eid"])
                sendPacket(packet, clientaddress)
        if DiwaliOpted:
            if currentDate == festivalDates["Diwali"]:
                packet = createPacket(
                    0, 0, festivalMessages["Diwali"])
                sendPacket(packet, clientaddress)
        if ChristmasOpted:
            if currentDate == festivalDates["Christmas"]:
                packet = createPacket(0, 0, festivalMessages["Christmas"])
                sendPacket(packet, clientaddress)
        if EasterOpted:
            if currentDate == festivalDates["Easter"]:
                packet = createPacket(
                    0, 0, festivalMessages["Easter"])
                sendPacket(packet, clientaddress)

        newDay()

    # newDay()


def generatecheckSum(packet):
    h = hashlib.new('md5')
    h.update(pickle.dumps(packet))

    return h.digest()


def isCorrupt(packet):
    seq_num = packet[0:4]
    ack_flag = packet[4:8]
    pay_len = packet[8:12]
    payloadLength = int.from_bytes(pay_len, byteorder='big')
    payload = packet[12:payloadLength+12]

    check_sum = packet[payloadLength+12:]
    packet_to_check = seq_num + ack_flag + pay_len + payload

    new_checksum = checksum(packet_to_check)

    if check_sum == new_checksum:
        return False

    elif check_sum != new_checksum:
        return True


def checksum(pkt):
    h = hashlib.new('md5')
    h.update(pickle.dumps(pkt))

    return h.digest()


def is_ack(packet):
    ack_flag = int.from_bytes(packet[4:8], "big")

    if ack_flag == 1:
        return True
    else:
        return False


def seq_mismatch(packet):
    seq = packet[:4]

    if seq != 0:
        return True
    else:
        return False


def start():
    while True:
        print("SERVER RUNNING")
        data, addr = serverSock.recvfrom(1024)
        packet = data

        if not isCorrupt(packet):
            print("REQUEST RECEIVED!")
            print("SENDING ACKNOWLEDGEMENT PACKET...")
            ack_packet = createPacket(0, 1, " ")
            sendPacket(ack_packet, addr)
        else:
            print("ERROR... CORRUPTED PACKET. ASKING CLIENT TO RESEND...")

        pay_len = int.from_bytes(packet[8:12], "big")
        payload = packet[12:pay_len+12]
        festivals = payload.decode("ascii")[:pay_len]

        festivallist = [x.strip() for x in festivals.split(',')]

        main(festivallist, addr)

        break
    closeSocket()


start()
