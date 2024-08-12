import subprocess
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def execute_firewall_command(command):
    """
    Execute the given firewall command and return the output.
    """
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {command}\n{e.output.decode('utf-8')}")
        return None

def apply_security_policy(threat_intelligence_data):
    """
    Apply security policy based on the provided threat intelligence data.
    """
    logging.info("Resetting firewall rules.")
    execute_firewall_command("netsh advfirewall reset")

    logging.info("Setting default policies.")
    execute_firewall_command("netsh advfirewall set allprofiles state on")

    logging.info("Applying threat intelligence data.")
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
            logging.info(f"Applied rule: {command}")

    logging.info("Saving firewall rules.")
    execute_firewall_command("netsh advfirewall export C:\\firewall_rules.wfw")

def disable_autorun():
    """
    Disable autorun for all drives.
    """
    command = 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f'
    execute_firewall_command(command)
    logging.info("Autorun disabled for all drives.")

def disable_usb_storage():
    """
    Disable USB storage devices.
    """
    command = 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f'
    execute_firewall_command(command)
    logging.info("USB storage devices disabled.")

def restrict_device_installation():
    """
    Restrict installation of devices.
    """
    command = 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions" /v DenyDeviceIDs /t REG_MULTI_SZ /d "USBSTOR\\DISK" /f'
    execute_firewall_command(command)
    logging.info("Device installation restricted.")

def get_groups_to_block():
    """
    Get the list of groups to block from the user.
    """
    available_groups = ["Users", "Guests", "Power Users", "Remote Desktop Users", "Network Configuration Operators"]
    print("Available groups to block:")
    for i, group in enumerate(available_groups, 1):
        print(f"{i}. {group}")
    
    group_indices = input("Enter the numbers of the groups you want to block, separated by commas: ")
    selected_groups = [available_groups[int(index) - 1] for index in group_indices.split(",") if index.strip().isdigit() and 0 < int(index) <= len(available_groups)]
    
    return selected_groups

def restrict_access_to_directories(directories):
    """
    Restrict access to important directories on the C: drive from external devices.
    """
    groups_to_block = get_groups_to_block()
    
    for directory in directories:
        for group in groups_to_block:
            command = f'icacls "{directory}" /deny "{group}":(OI)(CI)R'
            execute_firewall_command(command)
            logging.info(f"Access restricted to: {directory} for {group} group")

def whitelist_ip():
    """
    Whitelist an IP address provided by the user.
    """
    ip = input("Enter the IP address to whitelist: ")
    port = input("Enter the port to whitelist (or press Enter to skip): ")
    direction = input("Enter the direction (in/out, default is in): ").lower() or "in"
    protocol = input("Enter the protocol (TCP/UDP, default is TCP): ").upper() or "TCP"
    
    if port:
        command = f"netsh advfirewall firewall add rule name=\"Whitelist\" dir={direction} action=allow protocol={protocol} localport={port} remoteip={ip}"
    else:
        command = f"netsh advfirewall firewall add rule name=\"Whitelist\" dir={direction} action=allow remoteip={ip}"
    
    execute_firewall_command(command)
    logging.info(f"Whitelisted IP: {ip} with command: {command}")

def main():
    # Example threat intelligence data
    threat_intelligence_data = [
        {'ip': '192.168.1.100', 'action': 'block'},
        {'ip': '10.0.0.50', 'action': 'block', 'port': '80', 'protocol': 'TCP', 'direction': 'in'},
        {'ip': '172.16.0.1', 'action': 'allow', 'port': '443', 'protocol': 'TCP', 'direction': 'in'},
    ]
    important_directories = [
        'C:\\Windows',
        'C:\\Program Files',
        'C:\\Program Files (x86)',
        'C:\\Users\\Public'
    ]
    apply_security_policy(threat_intelligence_data)
    disable_autorun()
    disable_usb_storage()
    restrict_device_installation()
    restrict_access_to_directories(important_directories)
    
    # Whitelist IP based on user input
    whitelist_choice = input("Do you want to whitelist an IP address? (yes/no): ").lower()
    if whitelist_choice == 'yes':
        whitelist_ip()

    logging.info("Security policy applied successfully.")

if __name__ == "__main__":
    main()
