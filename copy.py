import socket
import struct
import argparse, socket
from datetime import datetime
from uuid import getnode as get_mac
from random import randint

MAX_BYTES = 65535


def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb

class DHCPDiscover:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t) 

    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transactionID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + macb
        packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet


class DHCPOffer:
    def __init__(self, data):
       # self.data = data
       # self.transID = transID
       # self.offerIP = ''
       # self.nextServerIP = ''
       # self.DHCPServerIdentifier = ''
       # self.leaseTime = ''
       # self.router = ''
       # self.subnetMask = ''
       # self.DNS = []

         self.transID = data[4:8]
       # print(self.transID)
       # print(self.transID)
       # self.unpack()
    
    def unpack(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x02'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
       # packet += self.transactionID       #Transaction ID
        packet += self.transID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x00\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\xc0\xa8\xeb\x8d'   #Your (client) IP address: 192.168.235.141
        packet += b'\xc0\xa8\xeb\x86'   #Next server IP address: 192.168.235.134
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x02'               #option 53   #Option: (t=53,l=1) DHCP Message Type = DHCP Offer
        packet += b'\x01\x04\xff\xff\xff\x00'   #option 1
        packet += b'\x03\x04\xc0\xa8\xeb\x02'   #option 3
        packet += b'\x33\x04\x00\x00\x07\x08'   #option 51
        packet += b'\x36\x04\xc0\xa8\xeb\xfe'   #option 54
        packet += b'\x06\x04\xc0\xa8\xeb\x02'   #option 6  
         
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        #packet += b'\x3d\x06' + macb
       # packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet


class DHCPRequest:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t)

    def repack(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
       # packet += self.transactionID       #Transaction ID
        packet += self.transactionID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x00\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\xc0\xa8\xeb\x8d'   #Your (client) IP address: 192.168.77.77
        packet += b'\xc0\xa8\xeb\x86'   #Next server IP address: 192.168.235.134
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x03'               #option 53   #Option: (t=53,l=1) DHCP Message Type = DHCP Offer
        packet += b'\x3d\x06'   #option 50..  + macb
        packet += b'\x36\x04\xc0\xa8\xeb\xfe'   #option 54

        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        #packet += b'\x3d\x06' + macb
       # packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet



class DHCPAck:
    def __init__(self, data):

         self.transID = data[4:8]

    def ackpack(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x02'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
       # packet += self.transactionID       #Transaction ID
        packet += self.transID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x00\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\xc0\xa8\xeb\x8d'   #Your (client) IP address: 192.168.235.141
        packet += b'\xc0\xa8\xeb\x86'   #Next server IP address: 192.168.235.134
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x05'               #option 53   #Option: (t=53,l=1) DHCP Message Type = DHCP Offer
        packet += b'\x01\x04\xff\xff\xff\x00'   #option 1
        packet += b'\x03\x04\xc0\xa8\xeb\x02'   #option 3
        packet += b'\x33\x04\x00\x00\x07\x08'   #option 51
        packet += b'\x36\x04\xc0\xa8\xeb\xfe'   #option 54
        packet += b'\x06\x04\xc0\xa8\xeb\x02'   #option 6  

        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        #packet += b'\x3d\x06' + macb
       # packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet



def server():
        dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        dhcps.bind(('0.0.0.0',67))
        while True:
                data , address = dhcps.recvfrom(MAX_BYTES) #receive discover
               # print(address)
                offerPacket = DHCPOffer(data)
                dhcps.sendto(offerPacket.unpack(), ('255.255.255.255', 9527)) #send offer
                data2 , address2 = dhcps.recvfrom(MAX_BYTES) #receive request
                ackPacket = DHCPAck(data2)
                dhcps.sendto(ackPacket.ackpack(), ('255.255.255.255', 9527)) #send ack



def client():
        dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        dhcps.bind(('0.0.0.0',9527))
        discoverPacket = DHCPDiscover()
        dhcps.sendto(discoverPacket.buildPacket(), ('255.255.255.255', 67)) # send discover
        data, address = dhcps.recvfrom(MAX_BYTES)  #receive offer
       # print(address)
        requestPacket = DHCPRequest()
        dhcps.sendto(requestPacket.repack(), ('255.255.255.255', 67)) #send request
        data2, address2 = dhcps.recvfrom(MAX_BYTES) #receive ack
       # print(address)

if __name__ == '__main__':
        choices = {'client': client,'server': server}
        parser = argparse.ArgumentParser(description='Send and receive UDP locally')
        parser.add_argument('role', choices=choices, help='which role to play')
        parser.add_argument('-p', metavar='PORT', type=int, default=1060, help='UDP port (default 1060)')
        args = parser.parse_args()
        function = choices[args.role]
        function()













