import subprocess
from lib_shared.common_config import *
def execute_firewall_command(command):
    """
    Execute the given firewall command and return the output.
    """
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}\n{e.output.decode('utf-8')}")
        return None

def apply_security_policy(threat_intelligence_data):
    """
    Apply security policy based on the provided threat intelligence data.
    """
    # Flush existing rules
    execute_firewall_command("netsh advfirewall reset")

    # Default policies
    execute_firewall_command("netsh advfirewall set allprofiles state on")

    # Apply rules from threat intelligence data
    for threat in threat_intelligence_data:
        ip = threat.get('ip')
        action = threat.get('action', 'block').lower()
        port = threat.get('port', None)
        direction = threat.get('direction', 'in').lower()
        protocol = threat.get('protocol', 'TCP').upper()
        
        if ip and action in ['allow', 'block']:
            if port:
                command = f"netsh advfirewall firewall add rule name=\"Threat {action}\" dir={direction} action={action} protocol={protocol} localport={port} remoteip={ip}"
            else:
                command = f"netsh advfirewall firewall add rule name=\"Threat {action}\" dir={direction} action={action} remoteip={ip}"
            execute_firewall_command(command)
            print(f"Applied rule: {command}")

    # Save firewall rules
    execute_firewall_command("netsh advfirewall export C:\\firewall_rules.wfw")

def disable_autorun():
    """
    Disable autorun for all drives.
    """
    command = 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f'
    execute_firewall_command(command)
    print("Autorun disabled for all drives.")

def disable_usb_storage():
    """
    Disable USB storage devices.
    """
    command = 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f'
    execute_firewall_command(command)
    print("USB storage devices disabled.")

def restrict_device_installation():
    """
    Restrict installation of devices.
    """
    command = 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions" /v DenyDeviceIDs /t REG_MULTI_SZ /d "USBSTOR\\DISK" /f'
    execute_firewall_command(command)
    print("Device installation restricted.")

def restrict_access_to_directories(directories):
    """
    Restrict access to important directories on the C: drive from external devices.
    """
    for directory in directories:
        command = f'icacls "{directory}" /deny Everyone:(OI)(CI)R'
        execute_firewall_command(command)
        print(f"Access restricted to: {directory}")

def apply_windows_policy():
    important_directories = []
    threat_intelligence_data = []
    # Example threat intelligence data
    ip_collection = db['Restricted_IP']
    ip_collection = ip_collection.find()
    for item in ip_collection:
        threat_intelligence_data.append({'ip':item['IP'],'action':'block'})
    dir_collection = db['Restricted_Directories']
    dir_collection= dir_collection.find()
    for item in dir_collection:
        if item['os']=='Windows':
            important_directories.append(item["directory"])
    print(important_directories)
    print(threat_intelligence_data)
    # threat_intelligence_data = [
    #     {'ip': '192.168.1.100', 'action': 'wi'},
    #     {'ip': '10.0.0.50', 'action': 'block', 'port': '80', 'protocol': 'TCP', 'direction': 'in'},
    #     {'ip': '172.16.0.1', 'action': 'allow', 'port': '443', 'protocol': 'TCP', 'direction': 'in'},
    # ]
    # important_directories = [
    #     'C:\\Windows',
    #     'C:\\Program Files',
    #     'C:\\Program Files (x86)',
    #     'C:\\Users\\Public'
    # ]
    # apply_security_policy(threat_intelligence_data)
    # disable_autorun()
    # disable_usb_storage()
    # restrict_device_installation()
    # restrict_access_to_directories(important_directories)
    # print("Security policy applied successfully.")

if __name__ == "__main__":
    main()
"""The error message indicates you need to run the netsh advfirewall reset command with administrator privileges. Here's how to fix it:

Open Command Prompt as Administrator:

Search for "Command Prompt" in the Start menu.
Right-click on "Command Prompt" and select "Run as administrator".
Execute the command:

In the elevated Command Prompt window, type the following command:

netsh advfirewall reset
Press Enter.

Running the command prompt as administrator grants it the necessary permissions to reset the firewall settings."""