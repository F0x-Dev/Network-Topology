import sys,os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Utils')))

from Utils.ip_sub import get_local_ip_and_subnet
from Utils.topology import create_network_topology

def main():
    ip, subnetmask = get_local_ip_and_subnet()
    print(f"IP: {ip}, Subnet Mask: {subnetmask}")

    create_network_topology(ip, subnetmask)

if __name__ == "__main__":

    main()
