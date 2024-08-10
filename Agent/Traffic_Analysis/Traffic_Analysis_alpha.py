import scapy.all as sc
import threading
import yara
from Traffic_Analysis import storage
from collections import defaultdict

data_consumed = defaultdict(int)
paths = []



tcp_rules = yara.compile('Traffic_Analysis/yara_rules/tcp.yara')
udp_rules = yara.compile('Traffic_Analysis/yara_rules/udp.yara')
icmp_rules = yara.compile('Traffic_Analysis/yara_rules/icmp.yara')
keyword_rules = yara.compile('Traffic_Analysis/yara_rules/offensive_tools.yara')
sql_injection_rules = yara.compile('Traffic_Analysis/yara_rules/sqli.yara')

flag = True
def tcp(binary):
    matchs = []
    global tcp_rules
    global keyword_rules
    matchs.extend(tcp_rules.match(data=binary))
    matchs.extend(keyword_rules.match(data=binary))
    return matchs

def udp(binary):
    matchs = []
    global udp_rules
    global keyword_rules
    matchs.extend(udp_rules.match(data=binary))
    matchs.extend(keyword_rules.match(data=binary))
    return matchs

def icmp(packet):
    global icmp_rules
    matchs = []
    if packet[sc.ICMP].type not in [0,8]:
        matchs.extend(['icmp_type_abnormalities'])
    elif packet[sc.IP].len > 100:
        matchs.extend(['icmp_size_abnormalities'])
    else:
        matchs.extend(icmp_rules.match(data=packet.payload.original))
    if len(matchs) != 0:
        #print(packet[sc.IP].src.,matchs)
        return True
    return False

def extract_url(packet):
    if packet.haslayer(sc.IP) and packet.haslayer(sc.TCP) and packet.haslayer(sc.Raw):
        payload = packet[sc.Raw].load.decode('utf-8', errors='ignore')
        if payload.startswith("GET") or payload.startswith("POST"):
            headers = payload.split('\r\n')
            host = ''
            path = headers[0].split(' ')[1]  # Get the request path
            for header in headers:
                if header.startswith('Host:'):
                    host = header.split(' ')[1]  # Get the host
                    break

            if host and path:
                pool1 = threading.Thread(target = storage.domain_check, args = (host,))
                pool1.start()
                #url = f"http://{host}{path}"
                #print(f"URL: {url}")
                #paths.append(url)

def Output(info):
    global rules
    if info[0] == "TCP":
        matchs = tcp(info[2])
        if info[3] == 80:
            global sql_injection_rules
            matchs.extend(sql_injection_rules.match(data=info[2]))
        if len(matchs) != 0:
            #print(info[1],matchs)
            return True
    elif info[0] == "UDP":
        matchs = udp(info[2])
        if len(matchs) != 0:
            #print(info[1],matchs)
            return True
    else:
        pass
        #print(info)
    return False

def Istart(packets):
    ip_list = []
    for packet in packets:
        s_flag = False
        if packet.haslayer(sc.TCP) and packet.haslayer(sc.IP):
            src_ip = packet[sc.IP].src
            dst_ip = packet[sc.IP].dst
            if src_ip not in ip_list:
                ip_list.append(src_ip)
            if dst_ip not in ip_list:
                ip_list.append(dst_ip)
            data_length = len(packet)
            data_consumed[src_ip] += data_length
            data_consumed[dst_ip] += data_length
            data = packet[sc.TCP].payload.original
            info = ("TCP",src_ip,data,packet[sc.TCP].dport)
            s_flag = Output(info)
            extract_url(packet)

        elif packet.haslayer(sc.ICMP) and packet.haslayer(sc.IP):
            s_flag = icmp(packet)

        elif packet.haslayer(sc.UDP) and packet.haslayer(sc.IP):
            src_ip = packet[sc.IP].src
            dst_ip = packet[sc.IP].dst
            if src_ip not in ip_list:
                ip_list.append(src_ip)
            if dst_ip not in ip_list:
                ip_list.append(dst_ip)
            data_length = len(packet)
            data_consumed[src_ip] += data_length
            data_consumed[dst_ip] += data_length
            data = packet[sc.UDP].payload.original
            info = ("UDP",src_ip,data)
            s_flag = Output(info)

        elif packet.haslayer(sc.DNS) and packet.haslayer(sc.IP):
            info = ("DNS",packet[sc.IP].src,str(packet.payload[2]))
            Output(info)

        elif packet.haslayer(sc.ARP):
            if packet[sc.ARP].op == 1:
                info = ("ARP",packet[sc.ARP].hwsrc,packet[sc.ARP].psrc,"who-has")
                Output(info)
            elif packet[sc.ARP].op == 2:
                info = ("ARP",packet[sc.ARP].hwsrc,packet[sc.ARP].psrc,"is-at")
                Output(info)

        else:
            pass
        if s_flag:
            storage.write_pcap(packet)
    if len(ip_list) != 0:
        pool2 = threading.Thread(target = storage.ip_check, args = (ip_list,))
        pool2.start()


def capture():
    collection = []
    pointer = 0
    global flag
    while flag:
        packets = sc.sniff(count = 200,timeout = 2)
        collection.append(threading.Thread(target = Istart, args = (packets,)))
        collection[pointer].start()
        pointer += 1
        if pointer == 20:
            pointer = 0
            collection.clear()

def traffic_usage():
    for ip,data in data_consumed.items():
        print(f"IP: {ip}, Data consumed: {data / 1024:.2f} KB")

def run():
    global flag
    flag = True
    pool = threading.Thread(target = capture, args = "")
    pool.start()

def stop():
    global flag
    flag = False

if __name__ == "__main__":
    pool = threading.Thread(target = capture, args = "")
    pool.start()
    try:
        i = input("\n Enter Anything to stop \n ")
        flag = False
    except KeyboardInterrupt:
        flag = False
    pool.join()
    for ip,data in data_consumed.items():
        print(f"IP: {ip}, Data consumed: {data / 1024:.2f} KB")