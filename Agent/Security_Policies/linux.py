import subprocess
from lib_shared.common_config import *

def execute_command(command):
    """
    Execute the given command and return the output.
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
    execute_command("iptables -F")
    execute_command("iptables -X")


    # Apply rules from threat intelligence data
    for threat in threat_intelligence_data:
        ip = threat.get('ip')
        action = threat.get('action', 'DROP').upper()
        port = threat.get('port', None)
        direction = threat.get('direction', 'INPUT').upper()
        protocol = threat.get('protocol', 'TCP').lower()


        if ip and action in ['ACCEPT', 'DROP']:
            if port:
                command = f"iptables -A {direction} -p {protocol} --dport {port} -s {ip} -j {action}"
            else:
                command = f"iptables -A {direction} -s {ip} -j {action}"
            execute_command(command)
            print(f"Applied rule: {command}")


    # Save firewall rules
    execute_command("iptables-save > /etc/iptables/rules.v4")


def disable_autorun():
    """
    Disable autorun for all drives.
    """
    # Create a udev rule to disable autorun
    autorun_rule = """
    ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[a-z][0-9]", ENV{UDISKS_PRESENTATION_HIDE}="1"
    """
    with open("/etc/udev/rules.d/99-disable-autorun.rules", "w") as f:
        f.write(autorun_rule)
    execute_command("udevadm control --reload-rules")
    print("Autorun disabled for all drives.")


def disable_usb_storage():
    """
    Disable USB storage devices.
    """
    # Create a udev rule to disable USB storage
    usb_storage_rule = """
    ACTION=="add", SUBSYSTEM=="usb", ATTR{product}=="USB Mass Storage", ATTR{authorized}="0"
    """
    with open("/etc/udev/rules.d/99-disable-usb-storage.rules", "w") as f:
        f.write(usb_storage_rule)
    execute_command("udevadm control --reload-rules")
    print("USB storage devices disabled.")


def restrict_device_installation():
    """
    Restrict installation of devices.
    """
    # Create a udev rule to restrict device installation
    device_install_rule = """
    ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", ATTR{authorized}="0"
    """
    with open("/etc/udev/rules.d/99-restrict-device-install.rules", "w") as f:
        f.write(device_install_rule)
    execute_command("udevadm control --reload-rules")
    print("Device installation restricted.")


def restrict_access_to_directories(directories):
    """
    Restrict access to important directories on the system from external devices.
    """
    for directory in directories:
        command = f'chmod -R o-rwx "{directory}"'
        execute_command(command)
        print(f"Access restricted to: {directory}")


def apply_linux_policy():
    important_directories = []
    threat_intelligence_data = []
    # Example threat intelligence data
    ip_collection = db['Restricted_IP']
    ip_collection = ip_collection.find()
    for item in ip_collection:
        threat_intelligence_data.append({'ip':item['IP'],'action':'DROP'})
    dir_collection = db['Restricted_Directories']
    dir_collection= dir_collection.find()
    for item in dir_collection:
        if item['os']=='Linux':
            important_directories.append(item["directory"])
    print(important_directories)
    print(threat_intelligence_data)
    # Example threat intelligence data
    # threat_intelligence_data = [
    #     {'ip': '192.168.1.100', 'action': 'DROP'},
    #     {'ip': '10.0.0.50', 'action': 'DROP', 'port': '80', 'protocol': 'tcp', 'direction': 'INPUT'},
    #     {'ip': '172.16.0.1', 'action': 'ACCEPT', 'port': '443', 'protocol': 'tcp', 'direction': 'INPUT'},
    # ]
    # important_directories = [
    #     '/etc',
    #     '/var',
    #     '/usr',
    #     '/home'
    # ]
    # apply_security_policy(threat_intelligence_data)
    # disable_autorun()
    # disable_usb_storage()
    # restrict_device_installation()
    # restrict_access_to_directories(important_directories)
    # print("Security policy applied successfully.")


if __name__ == "__main__":
    main()