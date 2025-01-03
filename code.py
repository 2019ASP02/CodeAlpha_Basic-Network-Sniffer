#import the library file for os and network handle 
import os
import sys
import socket
import struct
#define the method "sniffer" for create socket and its retrun created socket 
def sniffer():
    if os.name == 'nt':# if Windows NT os, os library used to find the os
        sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        host = socket.gethostname(socket.gethostname())
        sniffer_socket.bind((host,0))
        sniffer_socket.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        sniffer_socket.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
        print(f"Sniffer started on WIndows, host : {host}")
    elif os.name =='posix':# if UNix based distribution, os library used to find the os
        sniffer_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
        print("Sniffer started on Linux/Unix")
    else:#any other os 
        print("Unsupported platform.")
        sys.exit(1)
    return sniffer_socket # return the created socket

#define the "parse packet" Method parse(find) the packet details
def parse_packet(packet):
    eth_header = packet[:14] #first 14 :0-6(destination)+6(source)+2(protocol)
    eth_data = struct.unpack("!6s6sH",eth_header)#!6s6sH used to intrrupt the unpack binary data
    eth_protocol = socket.ntohs(eth_data[2]) # convert the Ethernet protocol type from network byte order
    packet_type = "IPv4" if eth_protocol == 8 else "Other" # ipv4 contain the 8 bit address else other protocol like ARP or IPv6
    if eth_protocol == 8: #ipv4 find the all below infrormation
        ip_header = packet[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s',ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4#extract the version field from the IP header.
        ihl = version_ihl & 0xF
        ttl = iph[5]
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])#convert a raw binary IP address into a readable string format for IPv4 addresses
        dest_ip = socket.inet_ntoa(iph[9])
#retrun the all the finding
        return {
            "Packet Type":packet_type,
            "Version": version,
            "TTL": ttl,
            "Source IP":src_ip,
            "Destination IP":dest_ip,
            "Protocol":protocol
        }
    return {"Packet Type": "Other"}# not IPv4 display the other type protocol

def main():
    try:# Try-Except Block for Error Handling
        sniffer_socket = sniffer()# create the socket
        print("Listening For packets...\n")
        while True:# loop run untill intrrupt occured
            raw_packet,_ = sniffer_socket.recvfrom(65535)# it capture the maximum size of ip packet
            parsed = parse_packet(raw_packet)#convert a raw packet into readable packet
            print(parsed)
    except KeyboardInterrupt:#if any keybord intrrupt occured "CTRL + C"
        print("\nStopping sniffer.")
        if os.name == 'nt':
            sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)# terminate the sinffer
    except Exception as e:#if any Exception occurs
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":#main function (execute first)
    main()