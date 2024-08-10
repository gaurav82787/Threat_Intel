import os
import hashlib
import requests
import json
import platform
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import gzip
import shutil
from pathlib import Path
import threading
from Traffic_Analysis import Traffic_Analysis_alpha as TA
from Traffic_Analysis import resource_monitor as RM
from datetime import date
import base64
import requests
import tarfile
from lib_shared.common_config import *
# Get the current date
current_date = date.today()


upload_server_path = f'http://{server_ip}:{server_port}/upload_file'
get_yara_url = f'http://{server_ip}:{server_port}/yara'
pcap_file_to_watch=f'Traffic_Analysis/Malicious_Capture/traffic_{current_date}.pcap'
log_files_to_watch.append(pcap_file_to_watch)


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
    
    def on_modified(self, event):
        if event.src_path == self.file_path:
            print(f'File {self.file_path} has been modified.')
            send_log_file(self.file_path)
def send_log_file(file_path):
    """Send the updated log file to the central server."""
    try:
        # Compress log file
        compressed_file_path = Path(file_path).with_suffix('.gz')
        with open(file_path, 'rb') as f:
            with gzip.open(compressed_file_path, 'wb') as gz_file:
                shutil.copyfileobj(f, gz_file)
        
        # Prepare payload
        with open(compressed_file_path, 'rb') as f:
            files = {'file': (compressed_file_path.name, f, 'application/gzip')}
            data =  {'file_name':compressed_file_path.name,'file_ext':file_path.rsplit('.',1)[1],'token':auth_token}
            response = requests.post(upload_server_path, files=files, data=data)
            if response.status_code == 200:
                print(f'Successfully sent {file_path} to {upload_server_path}')
            else:
                print(f'Failed to send {file_path} - Status code: {response.status_code}')
        
        # Remove compressed file after sending
        os.remove(compressed_file_path)
    except Exception as e:
        print(f'Error sending {file_path}: {e}')
def get_yara_rules():
    try:
        with requests.get(f'http://{server_ip}:{server_port}/yara', stream=True) as r:
            r.raise_for_status()
            with open('Traffic_Analysis/yara_rules/yara.gz', 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)   
        with tarfile.open('Traffic_Analysis/yara_rules/yara.gz', 'r:gz') as tar:
            tar.extractall(path='Traffic_Analysis/yara_rules/')
        print("Successfully Fetched Yara Rules")
        os.remove('Traffic_Analysis/yara_rules/yara.gz')
    except Exception as e:
        print(f"Error Fetching, Check Connection and Server Configurations{e}")
def main():
    """Main function to set up file monitoring."""
    print("Started")
    i = 0
    TA_thread=threading.Thread(target=TA.capture)
    Res_Monitor = threading.Thread(target=RM.main)
    event_handler={}
    observer={}
    for file_path in log_files_to_watch:  
        event_handler[i]= FileChangeHandler(file_path)
        observer[i] = Observer()
        observer[i].schedule(event_handler[i], path=os.path.dirname(file_path), recursive=False)
        # Start monitoring
        observer[i].start()
        i=i+1
    TA_thread.start()
    Res_Monitor.start()
    try:
        while True:
            pass
    except KeyboardInterrupt:
        for a in range(i):
            observer[a].stop()
        TA_thread.stop()
        RM.flag=False
        # Res_Monitor.stop()
        print('Stopped monitoring.')
    finally:
        for  a in range(i):
            observer[a].join()
        TA_thread.join()
        Res_Monitor.join()

def add_token(token):
    with open('secret', 'w') as f:
        f.writelines(token)
        print("Added Successfully")
def apply_security_policy():
    os_type = platform.system()
    # os_type='Windows'
    if os_type=="Linux":
        from Security_Policies import linux
        linux.apply_linux_policy()
    elif os_type=="Windows":
        from Security_Policies import windows
        windows.apply_windows_policy()

def options():
    parser = argparse.ArgumentParser(description='-aT <your_Token_to_add authentication>')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-aT', '--add_token', nargs=1, metavar=('token'), help='-aT <your_Token_to_add authentication>')
    group.add_argument('-vT', '--view_token', action='store_true', help='view saved token')
    group.add_argument('-sync', '--initialize', action='store_true', help='sync settings from server i.e get_yara_rules')
    group.add_argument('-aSP', '--apply_security_policy', action='store_true', help='apply security policies')
    group.add_argument('-CTI', '--Start_CTI_Agent', action='store_true', help='start interactive mode')
    args = parser.parse_args()
    if args.add_token:
        token= args.add_token
        add_token(token)
    elif args.view_token:
        print(auth_token)
    elif args.initialize:
        get_yara_rules()
    elif args.apply_security_policy:
        apply_security_policy()
    elif args.Start_CTI_Agent:
        if auth_token=="" or server_ip=="" or server_port=="":
            print("add Token|server_ip|server_port First")
        else:
            main()
    else:
        parser.print_help()

if __name__ == "__main__":
    options()