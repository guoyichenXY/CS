import os
import struct
import time
import select
import socket

ICMP_ECHO_REQUEST = 8  # ICMP type code for echo request messages
ICMP_ECHO_REPLY = 0  # ICMP type code for echo reply messages
ICMP_TimeExceeded = 11  # ICMP type code for time exceeded messages
ID = 0  # ID of icmp_header
SEQUENCE = 0  # sequence of icmp packets
MAX_HOPS = 30  # Maximum number of hops for traceroute


def checksum(data):
    csum = 0
    countTo = (len(data) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = data[count + 1] * 256 + data[count]
        csum += thisVal
        csum &= 0xffffffff
        count += 2
    if countTo < len(data):
        csum += data[len(data) - 1]
        csum &= 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum += (csum >> 16)
    answer = ~csum
    answer &= 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(icmpSocket, ID, timeout, destAddr, ttl):
    timeBeginReceive = time.time()
    whatReady = select.select([icmpSocket], [], [], timeout)
    timeInRecev = time.time() - timeBeginReceive
    if not whatReady[0]:
        return -1, ""
    timeReceived = time.time()
    recPacket, addr = icmpSocket.recvfrom(1024)
    byte_in_double = struct.calcsize("!d")
    # Unpack the packet header for useful information, including the ID
    ipHeader = recPacket[:20]
    icmpHeader = recPacket[20:28]
    icmp_type, icmp_code, icmp_checksum, icmp_packet_id, icmp_sequence = struct.unpack('!bbHHh', icmpHeader)
    # Check if the reply packet is for us
    if ID == icmp_packet_id:
        return timeReceived - timeBeginReceive, addr[0]
    elif timeInRecev > timeout:
        return -2, ""
    elif icmp_type == ICMP_TimeExceeded and icmp_code == 0:
        return -3, addr[0]
    else:
        return -1, ""


def sendOnePing(icmpSocket, destinationAddress, ID, ttl):
    icmp_checksum = 0
    icmp_header = struct.pack('!bbHHh', ICMP_ECHO_REQUEST, 0, icmp_checksum, ID, SEQUENCE)
    time_send = struct.pack('!d', time.time())
    icmp_checksum = checksum(icmp_header + time_send)
    icmp_header = struct.pack('!bbHHh', ICMP_ECHO_REQUEST, 0, icmp_checksum, ID, SEQUENCE)
    icmp_packet = icmp_header + time_send
    icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
    icmpSocket.sendto(icmp_packet, (destinationAddress, 80))


def doOnePing(destinationAddress, timeout, ttl):
    icmpName = socket.getprotobyname('icmp')
    icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmpName)
    sendOnePing(icmpSocket, destinationAddress, ID, ttl)
    data, addr = receiveOnePing(icmpSocket, ID, timeout, destinationAddress, ttl)
    icmpSocket.close()
    return data, addr


def traceroute(host, timeout):
    for ttl in range(1, MAX_HOPS):
        print(ttl, end="\t")
        # Calculate target IP address
        destAddr = socket.gethostbyname(host)
        # Perform the ping at the specified TTL
        data, addr = doOnePing(destAddr, timeout, ttl)
        if data == -1:
            print("*  *  *")
        elif data == -2:
            print("Time exceeded")
        else:
            print("{:.4f} ms\t{}".format(data * 1000, addr))
            # Check if the destination is reached
            if addr == destAddr:
                break
        time.sleep(1)


if __name__ == '__main__':
    while True:
        try:
            hostName = input("Input ip/name of the host you want: ")
            timeout = int(input("Input timeout: "))
            traceroute(hostName, timeout)
            break
        except Exception as e:
            print(e)
            continue
