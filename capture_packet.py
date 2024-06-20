from scapy.all import *
from scapy.layers.inet import TCP, IP

def read_tcp_options(packet):
    if packet.haslayer(TCP):
        # Kiểm tra xem gói tin có lớp IP và TCP không
        if packet.haslayer(IP) and packet[IP].src == "172.31.20.199":  # Kiểm tra IP nguồn của gói tin
            tcp_options = packet[TCP].options
            if tcp_options:
                binary_message = ""
                # In ra các tùy chọn của gói tin TCP
                for option in tcp_options:
                    # Kiểm tra xem giá trị của tùy chọn có phải là một chuỗi không
                    if isinstance(option[1], bytes):
                        try:
                            string = option[1].decode('utf-8')
                            # Kiểm tra xem chuỗi có bắt đầu bằng '1' không và có độ dài ít nhất là 4 ký tự không
                            if string.startswith('1') and len(string) >= 4:
                                # Thêm giá trị y vào chuỗi tất cả giá trị y
                                binary_message += string[3]
                        except UnicodeDecodeError:
                            continue
                return binary_message
    return ''

def read_pcap_file(pcap_file):
    # Đọc các gói tin từ tệp pcap
    packets = rdpcap(pcap_file)
    s = ''

    # Lặp qua từng gói tin và in trường options của gói tin TCP từ IP 172.31.20.199
    for packet in packets:
        s += read_tcp_options(packet)
    bytes_list = [s[i:i+8] for i in range(0, len(s), 8)]
    # Chuyển đổi từng byte thành ký tự Unicode
    message = ''.join([chr(int(byte, 2)) for byte in bytes_list])
    print(s)
    print(message, end="")

# Thay đổi tên tệp pcap thành tên tệp bạn muốn đọc
pcap_file = "capture_tcp_packet.pcapng"

# Đọc và in trường options của các gói tin TCP từ IP 172.31.20.199 trong tệp pcap
read_pcap_file(pcap_file)
