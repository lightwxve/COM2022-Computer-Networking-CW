# FestivalClient.py
import hashlib
import pickle
import socket

HEADER = 2048
PORT = 1111
FORMAT = 'ascii'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = ("127.0.0.1", 6789)

socket_object = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket_object.settimeout(5)
socket_object.connect(ADDR)

def buildPacket(sequenceNum, ackFlag, payload):
    payload = payload.encode("ascii")
    payloadLength = len(payload)
    sequenceAck = sequenceNum + payloadLength

    sequenceAck = sequenceAck.to_bytes(4, byteorder="big")
    ackFlag = ackFlag.to_bytes(4, byteorder="big")
    payloadLength = payloadLength.to_bytes(4, byteorder="big")

    packetToCheck = sequenceAck + ackFlag + payloadLength + payload
    serverChecksum = checksum(packetToCheck)

    full_packet = sequenceAck + ackFlag + payloadLength + payload + serverChecksum

    return full_packet

def checksum(pkt):
    h = hashlib.new('md5')
    h.update(pickle.dumps(pkt))
    # Checksum wont match because of hexdigest.
    return h.digest()

def isAck(packet):
    ackFlag = int.from_bytes(packet[4:8], "big")
    if ackFlag == 1:
        return True
    else:
        return False

def doSeqMatch(packet):
    seq = packet[:4]
    if seq != 0:
        return True
    else:
        return False

def notcorrupt(packet):
    sequenceNum = packet[0:4]
    ackFlag = packet[4:8]
    payloadLength = packet[8:12]
    payloadLength_toInt = int.from_bytes(payloadLength,byteorder='big')

    payload = packet[:payloadLength_toInt+12]
    clientChecksum = packet[payloadLength_toInt+12:] 
    
    remadePacket = sequenceNum + ackFlag + payloadLength + payloadLength
    serverChecksum  = checksum(remadePacket)

    if clientChecksum == serverChecksum:
        return False
    elif clientChecksum != serverChecksum:
        return True

def requestGreeting():
    socket_object.send(buildPacket(0, 0, "Easter"))
    print('[REQUEST SENT]')

while True:
    try:
        requestGreeting()
        ackPacket = socket_object.recv(PORT)
    except socket.timeout as e:
        print("[TIMEOUT]")
        continue

    if not(notcorrupt(ackPacket) or isAck(ackPacket)):
        print("[PACKET FAILED]")
        continue 
    else:
        print("[WAITING FOR GREETING]")
        try:
            greetingPacket = socket_object.recv(2048)
        except socket.timeout as inst:
            print("[TIMEOUT]")
            continue
        
        if not(notcorrupt(greetingPacket)):
            print("[PACKET CORRUPT]")
            continue
        else:
            pay_len = int.from_bytes(greetingPacket[8:12], "big")
            payload = greetingPacket[12:pay_len+12]
            print(payload)
            socket_object.close()
            break
