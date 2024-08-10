import scapy.all as sc
import base64
import logging
from lib_shared import alert
logging.basicConfig(filename='traffic.log', level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')
from datetime import date
from lib_shared.common_config import *
# Get the current date
database = client["Threat_Intel"]
collection_ip = database["CTI_mal_ip"]
collection_domain = database["CTI_mal_domain"]

def ip_check(ips):
    global collection_ip
    for src in ips:
        result = collection_ip.find_one({'mal_ip': src})
        if result:
            alert.send_alert(url=f"http://{server_ip}:{server_port}/alert",
    category='IP',
    message=f'Suspicious IP detected : {result["mal_ip"]}',
    severity='Medium',
    description=f'Found Malicious IP from Sources : {result["source"]}',
    token= auth_token
)
            logging.warning(f"Connection: {src}")

def domain_check(domain):
    global collection_domain
    result = collection_ip.find_one({'mal_domain': domain})
    if result:
        alert.send_alert(url=f"http://{server_ip}:{server_port}/alert",
    category='Domain',
    message=f'Suspicious Domain detected : {result["mal_domain"]}',
    severity='Medium',
    description=f'Found Malicious Domain from Sources : {result["source"]}',
    token= auth_token
)
        logging.warning(f"Request-Response: {domain}")


current_date = date.today()
def write_pcap(packet):
    sc.wrpcap(f"Traffic_Analysis/Malicious_Capture/traffic_{current_date}.pcap",packet,append=True)

def mongodb(packet):
    global table
    ip = packet[sc.IP].src
    payload = base64.b64encode(packet.payload.original).decode()
    item = {"ip" : ip,
        "payload" : payload}
    x = table.insert_one(item)

def mysql(packet):
    global con
    cur = con.cursor()
    ip = packet[sc.IP].src
    payload = base64.b64encode(packet.payload.original).decode()
    query = f"insert into NewTable values('{ip}','{payload}');"
    cur.execute(query)
    con.commit()

def sql_close():
    global con
    con.close()
