from scapy.all import*
import hashlib

SERVER_IP = '54.71.128.194'
SERVER_PORT = 99
UPPER_CASE = 65 #65 -> A(dec value in ASCII table)
LOWER_CASE = 97 #97 -> a(dec value in ASCII table)

def encrypt_packets(packet):
    '''
    The func is encrypting the packet that got from the sniff
    :param: packet: sniffed packet
    :type packet: scapy
    :return: encrypted packet
    :rtype: string
    '''
    key = int(((packet[Raw].load).decode())[3:6]) * (-1)
    msg = ((packet[Raw].load).decode())[6:]
    encrypted_text = ((packet[Raw].load).decode())[:6]
    return encrypted_text + encrypt(msg, key)

def encrypt(packet, key):
    '''
    The func is encrypting the msg by the key
    :param packet: sniffed packet
    :param key: the key to encrypt
    :type packet: scapy
    :type key: int
    :return: encrypted packet
    :rtype: string
    '''
    msg = packet
    encrypted_text = ''
    packet_index = 0
    for c in msg:
        if c.isalpha() and packet_index % 2 == 0:
            if c.isupper():
                encrypted_c = chr((ord(c) - UPPER_CASE + key) % 26 + UPPER_CASE) 
            else:
                encrypted_c = chr((ord(c) - LOWER_CASE + key) % 26 + LOWER_CASE) 
        else:
            encrypted_c = c
        packet_index+=1
        encrypted_text += encrypted_c
    return encrypted_text

buffer = ''

def print_packet(packet):
    '''
    The func is printing the decrypted msg and sending the final msg 
    to the srver
    :param: packet: sniffed packet
    :type packet: scapy
    '''
    if packet[UDP].sport == 99:
        srcport = packet[UDP].dport
    else:
        srcport = packet[UDP].sport

    msg = encrypt_packets(packet)
    print(msg)
    
    global buffer
    if 'location data' in msg:
        buffer += str(msg[len(msg)-10:])

    if '10/10' in encrypt_packets(packet):
        md5_hash = hashlib.md5(buffer.encode()).hexdigest()
        msg_to_send = 'FLY008' + encrypt('location_md5=' + str(md5_hash) + ',airport=nevada25.84,time=15:52,lane=earth.jup,vehicle=2554,fly',8)
        full_msg = Ether() / IP(dst=SERVER_IP) / UDP(sport=srcport,dport=99) / Raw(load=msg_to_send)
        answer = srp1(full_msg, verbose=0)
        print(answer.show())

def find_msg(packet):
    '''
    The func is filtring the packet with data from requered server
    :param packet: sniffed packet
    :type packet: scapy
    :return: is it requered packet or not
    :rtype: bool
    '''
    return IP in packet and (packet[IP].dst == SERVER_IP or packet[IP].src == SERVER_IP) and Raw in packet

def main():
    pakcets = sniff(lfilter=find_msg,prn=print_packet)

if __name__ == "__main__":
    main()