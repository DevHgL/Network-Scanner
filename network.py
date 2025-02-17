from scapy.all import ARP, Ether, srp
import nmap
import socket
import struct
import fcntl
from dotenv import load_dotenv
import os

load_dotenv()
iface = os.getenv('INTERFACE')

def get_ip_range():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', iface[:15].encode('utf-8')))[20:24])
    netmask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s', iface[:15].encode('utf-8')))[20:24])
    
    ip_bin = struct.unpack('!I', socket.inet_aton(ip))[0]
    netmask_bin = struct.unpack('!I', socket.inet_aton(netmask))[0]
    network_bin = ip_bin & netmask_bin

    network = socket.inet_ntoa(struct.pack('!I', network_bin))
    cidr = 32 - (bin(~netmask_bin & 0xffffffff).count('1'))
    return f"{network}/{cidr}"

def mask_ip(ip_range):
    """Mascarar o IP para exibição pública"""
    return 'XXX.XXX.XXX.XXX/XX'

def scan_with_scapy(ip_range):
    print("Scanning with Scapy...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for device in devices:
        print("{:16}    {}".format(device['ip'], device['mac']))

def scan_with_nmap(ip_range):
    print("\nScanning with Nmap...")
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')
    for host in nm.all_hosts():
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())

if __name__ == "__main__":
    target_ip_range = get_ip_range()
    print(f"Target IP range detected: {mask_ip(target_ip_range)}")  # Exibe IP mascarado
    scan_with_scapy(target_ip_range)
    scan_with_nmap(target_ip_range)
