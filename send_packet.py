import random

from scapy.all import *
from scapy.layers.inet import IP,TCP

number = input("Input message: ")
dst_ip = input("Enter destination IP: ")
binary_representation = ''.join(format(ord(char), '08b') for char in number)

#Tạo mảng rồi trộn lẫn
packet_len=len(binary_representation)

#Tạo mảng gấp đôi số lượng phần tử để sinh 50%bit1 50%bit0
packet_array=['0']*2*packet_len
print(packet_len)
for i in range(0,packet_len):
    packet_array[i]='1'
random.shuffle(packet_array)
print(binary_representation)

#Tao cac goi tin
temp=0
update_packet_array =[]
for i in packet_array:
        if i=='1':
                random_string=''.join(random.choice(['0','1']) for _ in range(2))
                i+=random_string+binary_representation[temp]
                temp+=1
                update_packet_array.append(i)
        else:
                random_string = ''.join(random.choice(['0', '1']) for _ in range(3))
                i+=random_string
                update_packet_array.append(i)

# Tạo một gói tin TCP
tcp_packet = IP(dst='dst_ip', src='172.31.20.199') / TCP(sport=13337, dport=RandShort(), seq=RandShort(), ack=RandShort())

print(len(update_packet_array))
for x in update_packet_array:
        #IN thử giá trị
        print(x,end=" ")

        # Thêm TCP option với giá trị từ byte array đã tạo
        tcp_packet[TCP].options = [('MSS', x)]
        send(tcp_packet)
