import os
import sys
import socket
import struct

def sniffer:
    if os.name == 'nt':
        sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        host = socket.gethostname(socket.gethostname())
        sniffer_socket.bind((host,0))
        sniffer_socket.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        sniffer_socket.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
        print(f"Sniffer started on WIndows, host : {host}")
    elif os.name =='posix':
        sniffer_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
        print("Sniffer started on Linux/Unix")
    else:
        print("Unsupported platform.")
        sys.exit(1)
    return sniffer_socket
