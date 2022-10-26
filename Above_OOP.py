import argparse
import logging
import re
import subprocess
from os import makedirs
from os.path import exists
from time import strftime

import colorama
from colorama import Fore, Style
from scapy.all import *
from scapy.contrib.cdp import *
from scapy.contrib.dtp import *
from scapy.contrib.eigrp import *
from scapy.contrib.lldp import *
from scapy.contrib.ospf import *
from scapy.layers.hsrp import *
from scapy.layers.l2 import *
from scapy.layers.vrrp import *

colorama.init(autoreset=True)

print(Fore.LIGHTWHITE_EX + Style.BRIGHT + r"""
####################################################################################################
####################################################################################################
######P~~~!J5GB#####G~~~!YG#################B?!G##########5~~~75G#############5~~!5########G7~~Y####
######Y  .^.  .?####P  :~..:!JPB###########5:  .?B########J  :^..:!YG#########Y    !P####B7.   ?####
######Y  7&#G5JY####P. 7#BPJ~:.:!JP######G!  ?Y: :5#######Y  7#G57^..:!JP#####Y  ?J  7GBJ. 7J  ?####
######Y  :J5G#&&####P. 7##&&&G?.  !B###BJ. ~P#&B7  !G#####Y  7##&&#P!   !B####Y  7&G! .. ^5&Y  ?####
######Y  ..  .^J####P. 7&#GJ~..~JG####5^ :Y######P~ .JB###Y  ?&B57:.:!JG######Y  7###P~^Y###J  ?####
######Y  !#G5J!J####P. ^7^.:75B#######7  !B&######?  ^G###Y  ^~. :75B#########Y  7##########J  ?####
######Y  !##########P. :^. ^JG#########P^ .J####5^ .J#####Y  .~JG#############Y  7##########J  ?####
######Y  !##########P. 7#GY!. :75B#######J. ^PG7  7G######Y  7&###############Y  7##########J  ?####
######Y  !##########P. 7###&#P?. .!B######G7  . ^5########Y  7################Y  7##########J  ?####
######Y  !##########P. 7###BP?~..~?B######&P:   J#########Y  7################Y  7##########J  ?####
######Y  !##########P. !GJ~..^75B########B7  !?. ~P#######Y  7################Y  7##########J  ?####
######Y  !##########P   .:!YG##########BJ. ^5#&G!  7G#####J  7################Y  !##########J  ?####
######GYJP##########BYYYPB#############GJJYB#####5JJP#####GJJP################GJJP##########GYJP####
########&##################################################&&###################&#############&#####
####################################################################################################
""")
print(Fore.GREEN + Style.BRIGHT + "Sniff-based Network Vulnerability Scanner")
print(Fore.GREEN + Style.BRIGHT + "Author: Magama Bazarov, @in9uz, <in9uz@protonmail.com>")
print(Fore.WHITE + Style.BRIGHT + "To skip scanning some protocol during a full scan - hit" + Fore.BLUE + Style.BRIGHT + " CTRL + C")
print(Fore.WHITE + Style.BRIGHT + "All results will be in logs/ directory\n")

class Above(object):
    def __init__(self) -> None:
        self.LOG_FILENAME = "./logs/%s.log" % strftime("%Y%m%d-%H%M")
        self.self.args = self._argv_parse()
        makedirs("./logs/") if exists("./logs/") else None
        logging.basicConfig(filename=self.LOG_FILE, level=logging.INFO,
                            format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    def _argv_parse(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser()
        parser.add_argument("--interface", dest="interface", type=str, required=True, help="Specify your interface")
        parser.add_argument("--timeout", dest="timeout", type=int, required=True, help="Specify the timeout. How much time to sniff")
        parser.add_argument("--cdp", dest="cdp",  action='store_true', help="CDP Scan")
        parser.add_argument("--dtp", dest="dtp",  action='store_true', help="DTP Scan")
        parser.add_argument("--lldp", dest="lldp", action='store_true', help="LLDP Scan")
        parser.add_argument("--ospf", dest="ospf", action='store_true', help="OSPF Scan")
        parser.add_argument("--eigrp", dest="eigrp",  action='store_true', help="EIGRP Scan")
        parser.add_argument("--vrrp", dest="vrrp",  action='store_true', help="VRRP Scan")
        parser.add_argument("--hsrpv1", dest="hsrpv1", action='store_true', help="HSRPv1 Scan")
        parser.add_argument("--stp", dest="stp",  action='store_true', help="STP Scan")
        parser.add_argument("--llmnr", dest="llmnr",  action='store_true', help="LLMNR Scan")
        parser.add_argument("--nbns", dest="nbns",  action='store_true', help="NBNS Scan")
        parser.add_argument("--dhcpv6", dest="dhcpv6", action='store_true', help="DHCPv6 Scan")
        parser.add_argument("--fullscan", dest="fullscan", action='store_true', help="Scan all protocols")
        return parser.parse_args()

    def _hex_to_string(self, hex: str) -> str:
        '''
        Converts the hex string to the correct value for the OSPF password
        '''
        return bytes.fromhex(hex[2:] if hex[:2] == '0x' else hex).decode('utf-8')
    
    def _ospf_null_auth(self) -> None:
        logging.log("[!] OSPF Authentication isn't used.")

    def _ospf_simple_auth(self, auth_data: Any) -> None:
        logging.info("[*] Simple OSPF Authentication is used")
        logging.info("[*] Plaintext Password: " + self._hex_to_string(hex(auth_data)))

    def _ospf_crypt_auth(self, ospf_key_id: Any, auth_data_length: Any, auth_seq: Any) -> None:
        logging.log("\n[!] MD5 Auth is detected. Bruteforce it.")
        logging.log("[*] Tools: Ettercap, John the Ripper")
        logging.log("[*] OSPF Key ID is: " + str(ospf_key_id))
        logging.log("[*] Crypt data length: " + str(auth_data_length))
        logging.log("[*] Crypt Auth Sequence Number: " + str(auth_seq))
    
    def dhcpv6_sniff(self, pkt: Any) -> bool:
        if IPv6 in pkt:
            pkt[0][IPv6].dst == "ff02::1:2" # dhcpv6_dst_addr
            return True
        return False
    
    def detect_cdp(self) -> None:
        print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the CDP protocol...")
        snapcode = None
        try:
            cdp_frame = sniff(filter="ether dst 01:00:0c:cc:cc:cc", count=1, timeout=self.args.timeout, iface=self.args.interface)
            snapcode = cdp_frame[0][SNAP].code
        except:
            logging.error("\n[!] Error. CDP isn't detected.")
            return
        if snapcode == 0x2000:
            cdp_hostname = cdp_frame[0][CDPMsgDeviceID].val
            cdp_hardware_version = cdp_frame[0][CDPMsgSoftwareVersion].val
            cdp_port_id = cdp_frame[0][CDPMsgPortID].iface
            cdp_hardware_platform = cdp_frame[0][CDPMsgPlatform].val
            logging.info("\n[*] Info: Detected vulnerable CDP")
            logging.info("[*] Impact: Information Gathering, DoS Attack via CDP Flooding")
            logging.info("[*] Tools: Yersinia, Wireshark")
            logging.info("[*] Hostname is: " + str(cdp_hostname.decode()))
            logging.info("[*] Target Version: " + str(cdp_hardware_version.decode()))
            logging.info("[*] Target Platform: " +  str(cdp_hardware_platform.decode()))
            logging.info("[*] Your port: " + str(cdp_port_id.decode()))
            if cdp_frame[0].haslayer(CDPAddrRecordIPv4):
                cdp_addr = cdp_frame[0][CDPAddrRecordIPv4].addr  
                logging.info ("[*] Target IP Address: "  + cdp_addr)
        if snapcode == 0x2004:
            logging.info ("[!] Detected DTP. Skipping... Run the script again!")

    def detect_lldp(self) -> None:
        print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the LLDP protocol...")
        try:
            lldp_frame = sniff(filter="ether dst 01:80:c2:00:00:0e", count=1, timeout=self.args.timeout, iface=self.args.interface)
            lldp_port_id = lldp_frame[0][LLDPDUPortDescription].description
            lldp_system_name = lldp_frame[0][LLDPDUSystemName].system_name
            lldp_description = lldp_frame[0][LLDPDUSystemDescription].description
            logging.info("[*] Info: Detected vulnerable LLDP")
            logging.info("[*] Impact: Information Gathering")
            logging.info("[*] Tools: Wireshark")
            logging.info("[*] Your Port ID : "  + str(lldp_port_id.decode()))
            logging.info("[*] Target Hostname : "  + str(lldp_system_name.decode()))
            logging.info("[*] Target OS Version : "  + str(lldp_description.decode()))
        except:
            logging.error("\n[!] Error. LLDP isn't detected.")
            return
        
    def detect_dtp(self):
        print (Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the DTP protocol...")
        try:
            dtp_frame = sniff(filter="ether dst 01:00:0c:cc:cc:cc", count=1, timeout=self.args.timeout, iface=self.args.interface)
            dtp_snapcode = dtp_frame[0][SNAP].code
            if dtp_snapcode == 0x2004:
                dtp_neighbor = dtp_frame[0][DTPNeighbor].neighbor
                logging.info("[*] Info: Detected vulnerable DTP")
                logging.info("[*] Impact: VLAN Segmenation Bypassing")
                logging.info("[*] Tools: Yersinia, Scapy")
                logging.info("[*] DTP Neighbor is : "  + str(dtp_neighbor))
            if dtp_snapcode == 0x2000:
                logging.info("[!] Detected CDP. Skipping... Run the script again!")
        except:
            logging.error("[!] Error. DTP isn't detected.")
            return

    def detect_ospf(self):
        print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the OSPF protocol...")
        try:
            ospf_packet = sniff(filter="ip dst 224.0.0.5", count=1, iface=self.args.interface, timeout=self.args.timeout)
            area_id = ospf_packet[0][OSPF_Hdr].area
            auth_type = ospf_packet[0][OSPF_Hdr].authtype
            ospf_key_id = ospf_packet[0][OSPF_Hdr].keyid
            auth_data_length = ospf_packet[0][OSPF_Hdr].authdatalen
            auth_seq = ospf_packet[0][OSPF_Hdr].seq
            hello_source = ospf_packet[0][OSPF_Hdr].src
            logging.info("[*] Info: Detected vulnerable OSPF. Here is a little information about the autonomous system")
            logging.info("[*] Impact: Network Intelligence, MITM, DoS, Blackhole.")
            logging.info("[*] Tools: Loki, Scapy, FRRouting")
            logging.info("[*] Your OSPF area ID: "  + str(area_id))
            logging.info("[*] Your OSPF Neighbor: "  + str(hello_source))
            if auth_type == 0x00:
                self._ospf_null_auth()
            if auth_type == 0x01:
                self._ospf_simple_auth(ospf_packet[0][OSPF_Hdr].authdata)
            if auth_type == 0x02:
                self._ospf_crypt_auth(ospf_key_id, auth_data_length, auth_seq)
        except:
            logging.error("[!] Error. OSPF isn't detected.")
            return

    def detect_eigrp(self) -> None:
        print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the EIGRP protocol...")
        try:
            eigrp_packet = sniff(filter="ip dst 224.0.0.10", count=1, timeout=self.args.timeout, iface=self.args.interface)
            logging.info("[*] Info: Detected EIGRP. Here is a little information about the autonomous system")
            logging.info("[*] Impact: Network Intelligence, MITM, DoS, Blackhole.")
            logging.info("[*] Tools: Loki, Scapy, FRRouting")
            as_number = eigrp_packet[0][EIGRP].asn
            if eigrp_packet[0].haslayer("EIGRPAuthData"):
                logging.info("[!] There is EIGRP Authentication")
            eigrp_neighbor_ip = eigrp_packet[0][IP].src
            logging.info("[*] Your AS Number is " + str(as_number))
            logging.info("[*] Your EIGRP Neighbor is " + str(eigrp_neighbor_ip))
        except:
            logging.error("[!] Error. EIGRP isn't detected.")
            return 

    def detect_hsrpv1(self) -> None:
        pass

    def detect_vrrp(self) -> None:
        pass

    def detect_stp(self) -> None:
        pass

    def detect_llmnr(self) -> None:
        pass

    def detect_nbns(self) -> None:
        pass

    def detect_dhcpv6(self) -> None:
        pass

    def switch_to_promisc(self, interface) -> None:
        pass

def main():
    pass

if __name__ == "__main__":
    main()