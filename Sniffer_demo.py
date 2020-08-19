import socket
import struct
import textwrap


def main():
    conn = socket.socket(socket.AF_INET , socket.SOCK_RAW,socket.IPPROTO_IP)
    # create a raw socket and bind it to the public interface
    conn.bind((HOST, 0))
    # Include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # receives all packets
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        raw_data , addr = conn.recvfrom(65535)
        des_mac, src_mac, eth_proto,data = ethernet_frame(raw_data)
        print('\n Ethernet Frame:')
        print('destination : {},Source: {},Protocol: {}'.format(des_mac, src_mac, eth_proto))





#unpack ehternet
def ethernet_frame(data):
    des_mac , src_mac , proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(des_mac),get_mac_addr(src_mac),socket.htons(proto),data[14:]

#return mac address properly i.e(AA:BB:CC:DD)
def get_mac_addr(bytes_addr):

    bytes_addr = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_addr).upper()
    return mac_addr


main()