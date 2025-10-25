#!/usr/bin/env python3
#############################
# Author = Dirk Pawlaszczyk
#
# sample script to parse 
# nmap XML-informations
#############################

import sys
import xml.etree.ElementTree as ET

def parse_nmap_xml(filename):
    """Parse nmap XML file and extract open ports information"""
    try:
        tree = ET.parse(filename)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing XML file: {e}")
        sys.exit(1)
    
    ports = set()
    
    # Iterate through all hosts
    for host in root.findall('.//host'):
        # Check if host is up
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue
        
        # Get host address
        addr_elem = host.find('.//address[@addrtype="ipv4"]')
        if addr_elem is None:
            addr_elem = host.find('.//address[@addrtype="ipv6"]')
        if addr_elem is None:
            continue
        host_addr = addr_elem.get('addr')
        
        # Check both TCP and UDP ports
        for ports_elem in host.findall('.//ports'):
            for port in ports_elem.findall('port'):
                state_elem = port.find('state')
                if state_elem is None:
                    continue
                
                state = state_elem.get('state')
                
                # Skip filtered ports
                if 'filtered' in state:
                    continue
                
                # Only process open ports
                if state == 'open':
                    port_num = port.get('portid')
                    protocol = port.get('protocol')
                    
                    # Get service information
                    service = port.find('service')
                    if service is not None:
                        srv_name = service.get('name', '')
                        srv_product = service.get('product', '')
                        srv_version = service.get('version', '')
                        srv_extrainfo = service.get('extrainfo', '')
                    else:
                        srv_name = srv_product = srv_version = srv_extrainfo = ''
                    
                    # Add port to set
                    ports.add(int(port_num))
                    
                    # Print host information
                    print(f"{host_addr}\t{port_num}\t{srv_name}\t{srv_product}\t{srv_version}\t{srv_extrainfo}")
    
    return ports

def main():
    if len(sys.argv) <= 1:
        print("Generates a .txt file containing the open ports summary and the .nmap information\r")
        print("USAGE:\t./parsenmap.py <nmap xml file>\r\n")
        sys.exit(1)
    
    # Parse the nmap XML file
    ports = parse_nmap_xml(sys.argv[1])
    
    # Create port string for nmap command
    if ports:
        portstring = ','.join(str(p) for p in sorted(ports))
        print(f"sudo nmap -sS -p {portstring} -sV -A -vv -oA enumeration -iL ../ranges.txt")
    else:
        print("No open ports found")

if __name__ == "__main__":
    main()
