# FestivalClient.py
import hashlib
import pickle
import socket
import time

# create a socket with address and port
clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
clientSock.settimeout(60)
clientSock.connect(("127.0.0.1", 6789))


def create_packet(seq, ack, pay_load):
    # Creating packet with the format
    # Creating acknowledgement packet

    ack_flag = ack
    payload = pay_load
    pay_len = len(payload.encode("ascii"))
    seq_num = seq + pay_len

    # Need to pad the payload with extra characters since it is not at the maximum number of bytes
    # Padding payload with " " character

    payload = payload.encode("ascii")
    
    # Converting each number to 4 bytes as specified in RFC format
    seq_num = seq_num.to_bytes(4, byteorder="big")
    ack_flag = ack_flag.to_bytes(4, byteorder="big")
    pay_len = pay_len.to_bytes(4, byteorder="big")

    # Sequence number, Ack flag, payload length, payload, checkSum

    pkt_no_checksum = seq_num + ack_flag + pay_len + payload
    checksum_num = checksum(pkt_no_checksum)

    #checksum_num = checksum_num.encode('ascii')

    # Concatenate all together to create packet
    pkt = seq_num + ack_flag + pay_len + payload + checksum_num

    return pkt


def checksum(pkt):
    # Takes packet and passes into md5 to generate checkSum number
    h = hashlib.new('md5')
    h.update(pickle.dumps(pkt))
    # checksum doesn't match    
    return h.digest()



def is_ack(packet):
    # Sequence number, Ack flag, payload length, payload, checkSum

    ack_flag = int.from_bytes(packet[4:8], "big")

    if ack_flag == 1:
        return True
    else:
        return False


def seq_mismatch(packet):
    # Sequence number, Ack flag, payload length, payload, checkSum

    # recreate sequence number

    pay_len = int.from_bytes(packet[8:12], byteorder="big")
    new_seq = pay_len + 0
    seq = int.from_bytes(packet[:4], byteorder="big")

    if seq != new_seq:
        return True
    else:
        return False


def is_corrupt(packet):
    # Storing all packet items in variables
    seq_num = packet[0:4]
    ack_flag = packet[4:8]
    pay_len = packet[8:12]
    payloadLength = int.from_bytes(pay_len,byteorder='big')
    payload = packet[12:payloadLength+12]

    # Store checkSum number from packet into variable
    check_sum = packet[payloadLength+12:]

    # Recreating packet using: sequence number, Ack flag, payload length, payload without checkSum
    packet_to_check = seq_num + ack_flag + pay_len + payload

    # Passing packet into method to generate checkSum
    new_checksum = checksum(packet_to_check)

    # if checksum value is the same return false
    if check_sum == new_checksum:
        return False

    # if checksum value not the same return true
    elif check_sum != new_checksum:
        return True

    # sent the Message using the clientSock
    print('CLIENT RUNNING')

    # Sending a packet with the festival request to the server


def festival_request():
    clientSock.send(create_packet(0, 0, "Christmas"))
    print('FESTIVAL REQUEST SENT')


while True:

    # send festival request
    try:
        festival_request()
        print('waiting to receive acknowledgement')
        ack_pkt = clientSock.recv(1024)
    except socket.timeout as inst:
        print('TIMEOUT: 60 SECOND LIMIT HAS REACHED "%s"' % inst)
        print('SENDING FESTIVAL REQUEST AGAIN')
        continue

    if is_corrupt(ack_pkt):
        print("PACKET RECEIVED WAS CORRUPTED")
        continue

    # Checking if packet received IS an Acknowledgment
    elif not is_ack(ack_pkt):
        print("PACKET RECEIVED WAS NOT AN ACKNOWLEDGEMENT")
        continue

    # Checking if sequence number is correct
    elif seq_mismatch(ack_pkt):
        print("SEQUENCE MISMATCH ERROR")
        continue

    else:
        print("ACKNOWLEDGEMENT RECEIVED")
        print('waiting to receive greeting...')

        try:
            greeting_pkt = clientSock.recv(2048)
        except socket.timeout as inst:
            print('TIMEOUT: 60 SECOND LIMIT HAS REACHED FESTIVAL NOT RECEIVED "%s"' % inst)
            continue

        if is_corrupt(greeting_pkt):
            print("PACKET RECEIVED WAS CORRUPTED")
            continue

        # Checking if sequence number is correct
        elif seq_mismatch(ack_pkt):
            print("SEQUENCE MISMATCH ERROR")
            continue

        else:
            pay_len = int.from_bytes(greeting_pkt[8:12], "big")
            payload = greeting_pkt[12:pay_len+12].decode("ascii")
            print("GREETING RECEIVED ({})".format(payload))
            clientSock.close()
            break


