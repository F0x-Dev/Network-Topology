#https://scapy.readthedocs.io/en/latest/
from scapy.all import ARP, Ether, srp
import ipaddress
from Utils.ip_sub import get_local_ip_and_subnet

def get_router_ip(local_ip, subnet_mask):
    network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
    

    possible_router_ips = [str(network.network_address + 1), str(network.broadcast_address - 1)]
    
    for ip in possible_router_ips:
       
        arp_request = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = ether / arp_request
        
        answered, _ = srp(arp_request_broadcast, timeout=2, verbose=0)
        
        if answered:
            return answered[0][1].psrc 
            
    return None 

if __name__ == "__main__":
    ip,sub = get_local_ip_and_subnet()

    print(get_router_ip(ip,sub))
