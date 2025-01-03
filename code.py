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

def parse_packet(packet):
    eth_header = packet[:14]
    eth_data = struct.unpack("!6s6sH",eth_header)
    eth_protocol = socket.ntohs(eth_data[2])
    packet_type = "IPv4" if eth_protocol == 8 else "Other"

    if eth_protocol == 8:
        ip_header = packet[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s',ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        ttl = iph[5]
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])

        return {
            "Packet Type":packet_type,
            "Version": version,
            "TTL": ttl,
            "Source IP":src_ip,
            "Destination IP":dest_ip,
            "Protocol":protocol
        }
    return {"Packet Type": "Other"}

def main():
    try:
        sniffer_socket = sniffer()
        print("Listening For packets...\n")
        while True:
            raw_packet,_ = sniffer_socket.recvfrom(65535)
            parsed = parse_packet(raw_packet)
            print(parsed)
    except KeyboardInterrupt:
        print("\nStopping sniffer.")
        if os.name == 'nt':
            sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()