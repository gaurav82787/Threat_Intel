import psutil
import time
import logging
import threading
from lib_shared import alert
from lib_shared.common_config import *
# Define thresholds
CPU_USAGE_THRESHOLD = 60  # in percentage
MEMORY_USAGE_THRESHOLD = 60  # in percentage
DISK_USAGE_THRESHOLD = 90   

# Set up logging
logging.basicConfig(filename='system_monitor.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def check_cpu_usage():
    cpu_usage = psutil.cpu_percent(interval=1)
    if cpu_usage > CPU_USAGE_THRESHOLD:
        logging.warning(f"High CPU usage detected! Current usage: {cpu_usage}%")
        alert.send_alert(url=f"http://{server_ip}:{server_port}/alert",
    category='Resource Monitor',
    message=f'High CPU usage detected! ',
    severity='Medium',
    description=f"High CPU usage detected! Current usage: {cpu_usage}%",
    token= auth_token
)

def check_memory_usage():
    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.percent
    if memory_usage > MEMORY_USAGE_THRESHOLD:
        logging.warning(f"High Memory usage detected! Current usage: {memory_usage}%")
        alert.send_alert(url=f"http://{server_ip}:{server_port}/alert",
    category='Resource Monitor',
    message=f'High Memory usage detected! ',
    severity='Medium',
    description=f"High Memory usage detected! Current usage: {memory_usage}%",
    token= auth_token
)
        
def check_disk_usage():
    disk_usage = psutil.disk_usage('/').percent
    if disk_usage > DISK_USAGE_THRESHOLD:
        logging.warning(f"High Disk usage detected! Current usage: {disk_usage}%")
        alert.send_alert(url=f"http://{server_ip}:{server_port}/alert",
    category='Resource Monitor',
    message=f'High Disk usage detected! ',
    severity='Medium',
    description=f"High Disk usage detected! Current usage: {disk_usage}%",
    token= auth_token
)

def main():
    global flag
    while flag:
        check_cpu_usage()
        check_memory_usage()
        check_disk_usage()
        time.sleep(10)  # Wait for 10 seconds before checking again

flag = True
# if __name__ == "__main__":
#     pool = threading.Thread(target=main)
#     inp = input("Enter anything to stop \n")
#     flag = False
    