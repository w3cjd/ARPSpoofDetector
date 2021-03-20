'''
ARP Spoof Detector
Written by Christopher Dix, March 2021
'''
import os
from sys import platform


# Parse the ARP Table from a Windows system, Return dictionary of IP:MAC
def get_table_windows():
    # Retrieve ARP table from OS
    arp_command = os.popen('arp -a').read()
    # Variable to Store IP/MAC association
    arp_table = {}
    # Parse file line-by-line
    for line in arp_command.splitlines():
        # If it's a blank line skip it
        if len(line) == 0:
            continue
        # If the first or second char in the line is uppercase, skip that line, it's a label
        elif line[0].isupper() or line[2].isupper():
            continue
        else:
            # Remove the first two empty chars of indentation
            line = line[2:]
            # Check and skip multicast/broadcast/APIPA addresses, Must use try in case first octet is less than 3 digits
            try:
                first_octet = int(line[0:3])
                if (224 <= first_octet <= 239) or first_octet == 255 or first_octet == 169:
                    continue
            except:
                pass
            # Get IP address
            ip = line[0:line.index(' ')]
            # Check if Broadcast
            if ip[ip.index('.', ip.index('.', ip.index('.') + 1) + 1) + 1:] == "255":
                continue
            # Take IP out of line
            line = line[len(ip):].strip()
            # Get MAC address
            mac = line[0: line.index(' ')]
            # Store IP and MAC in Dictionary
            arp_table[ip] = mac
    return arp_table


def get_table_mac():
    # Retrieve ARP table from OS
    arp_command = os.popen('arp -a').read()
    # Variable to store IP/MAC association
    arp_table = {}
    

# Check OS platform and perform appropriate logic
if platform == 'win32':
    # Windows logic
    arpTable = get_table_windows()
    print(arpTable)
elif platform == 'darwin':
    arpTable = get_table_mac()
    # Mac logic
elif platform == 'linux':
    pass
    # Linux logic
else:
    print("Sorry, the current OS platform is not supported by this script.")
    exit(1)
