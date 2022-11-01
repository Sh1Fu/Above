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
        self.args = self._argv_parse()
        makedirs("./logs/") if not exists("./logs/") else None
        logging.basicConfig(filename=self.LOG_FILENAME, level=logging.INFO,
                            format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        logging.info("[*] Start scanning...")

    def _argv_parse(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser()
        parser.add_argument("--interface", dest="interface", type=str, required=True, help="Specify your interface")
        parser.add_argument("--timeout", dest="timeout", type=int, required=True, help="Specify the timeout. How much time to sniff")
        parser.add_argument("--fullscan", dest="fullscan", action='store_true', help="Scan all protocols")
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
        return parser.parse_args()

    def _hex_to_string(self, hex: str) -> str:
        '''
        Converts the hex string to the correct value for the OSPF password
        '''
        return bytes.fromhex(hex[2:] if hex[:2] == '0x' else hex).decode('utf-8')
    
    def _ospf_null_auth(self) -> None:
        logging.info("[!] OSPF Authentication isn't used.")

    def _ospf_simple_auth(self, auth_data: Any) -> None:
        logging.info("[*] Simple OSPF Authentication is used")
        logging.info("[*] Plaintext Password: " + self._hex_to_string(hex(auth_data)))

    def _ospf_crypt_auth(self, ospf_key_id: Any, auth_data_length: Any, auth_seq: Any) -> None:
        logging.info("\n[!] MD5 Auth is detected. Bruteforce it.")
        logging.info("[*] Tools: Ettercap, John the Ripper")
        logging.info("[*] OSPF Key ID is: " + str(ospf_key_id))
        logging.info("[*] Crypt data length: " + str(auth_data_length))
        logging.info("[*] Crypt Auth Sequence Number: " + str(auth_seq))
    
    def _dhcpv6_sniff(self, pkt: Any) -> bool:
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
            logging.error("[!] Error. CDP isn't detected.")
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
            logging.warning ("[!] Detected DTP. Skipping... Run the script again!")

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
            logging.error("[!] Error. LLDP isn't detected.")
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
            as_number = eigrp_packet[0][EIGRP].asn
            if eigrp_packet[0].haslayer("EIGRPAuthData"):
                logging.info("[!] There is EIGRP Authentication")
            eigrp_neighbor_ip = eigrp_packet[0][IP].src
            logging.info("[*] Info: Detected EIGRP. Here is a little information about the autonomous system")
            logging.info("[*] Impact: Network Intelligence, MITM, DoS, Blackhole.")
            logging.info("[*] Tools: Loki, Scapy, FRRouting")
            logging.info("[*] Your AS Number is " + str(as_number))
            logging.info("[*] Your EIGRP Neighbor is " + str(eigrp_neighbor_ip))
        except:
            logging.error("[!] Error. EIGRP isn't detected.")
        return 

    def _hsrpv1_check(self, packet: PacketList) -> None:
        '''
        Scan HSRPv1. Waiting five HSRP frames for test. Check auth types in frames
        '''
        for frame in range(0, 5, 1):
            if packet[frame][HSRP].state == 16 and packet[frame][HSRP].priority < 255:
                logging.info("[*] Info: Detected vulnerable HSRP value of ACTIVE Route")
                packet_sender_ip = packet[frame][IP].src
                packet_sender_mac = packet[frame][Ether].src
                packet_priority = packet[frame][HSRP].priority
                logging.info("[*] HSRPv1 Sender Value: " + str(packet_priority)) if frame != 0 else logging.info("[*] HSRPv1 ACTIVE Sender Value: " + str(packet_priority))
                logging.info("[*] HSRPv1 Sender IP: " + str(packet_sender_ip))
                logging.info("[*] HSRPv1 Sender MAC: " + str(packet_sender_mac))
                if packet[frame].haslayer(HSRPmd5):
                    logging.info ("[!] HSRP MD5 Authentication is used. You can bruteforce it.")
                    logging.info ("[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
                if packet[frame][HSRP].auth:
                    print ("[!] Simple HSRP Authentication is used.")
                    hsrpv1_plaintext = packet[frame][HSRP].auth
                    simple_hsrp_pass = hsrpv1_plaintext.decode("UTF-8")
                    logging.info("[!] HSRP Plaintext Password: " + simple_hsrp_pass)
                return

    def detect_hsrpv1(self) -> None:
        print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the HSRPv1 protocol...")
        try:
            hsrpv1_packet = sniff(count=5, filter="ip dst 224.0.0.2", iface=self.args.interface, timeout=self.args.timeout)
            self._hsrpv1_check(hsrpv1_packet)
        except:
            logging.error("[!] Error. HSRPv1 isn't detected.")
        return

    def detect_vrrp(self) -> None:
        print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the VRRP protocol...")
        try:
            vrrp_packet = sniff(filter="ip dst 224.0.0.18", count=1, timeout=self.args.timeout, iface=self.args.interface)
            vrrp_priority = vrrp_packet[0][VRRP].priority
            vrrp_auth_type = vrrp_packet[0][VRRP].authtype
            ip_src_packet = vrrp_packet[0][IP].src
            vrrp_mac_sender = vrrp_packet[0][Ether].src
            vrrp_all_auth_types = {
                0x0: "[!] VRRP Authentication is not used",
                0x1: "[*] Plaintext VRRP Authentication is used. Check this on Wireshark",
                254: "[*] VRRP MD5 Auth is used"
            }
            for prob_auth in vrrp_all_auth_types.keys():
                if vrrp_auth_type == prob_auth:
                    logging.info(vrrp_all_auth_types[prob_auth])
                    break
            if vrrp_priority <= 255:
                logging.info("[*] Info: Detected vulnerable VRRP Value")
                logging.info("[*] Impact: MITM")
                logging.info("[*] Tools: Scapy, Loki")
            logging.info("[*] VRRP Sender IP: " + ip_src_packet)
            logging.info("[*] VRRP Sender MAC: " + vrrp_mac_sender)
        except:
            logging.error("[!] Error. VRRP isn't detected.")
        return


    def detect_stp(self) -> None:
        print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the STP protocol...")
        try:
            stp_frame = sniff(filter="ether dst 01:80:c2:00:00:00", count=1, timeout=self.args.timeout, iface=self.args.interface)
            stp_root_mac = stp_frame[0][STP].rootmac
            stp_root_id = stp_frame[0][STP].rootid
            stp_root_pathcost = stp_frame[0][STP].pathcost
            logging.info("[*] Info: Detected vulnerable STP")
            logging.info("[*] Impact: MITM, VLAN ID Gathering. Check Root Bridge System ID Extension header in STP frame")
            logging.info("[*] Tools: Yersinia, Wireshark")
            logging.info("[*] STP Root MAC: " + str(stp_root_mac))
            logging.info("[*] STP Root ID: " + str(stp_root_id))
            logging.info("[*] STP Root Path Cost: " + str(stp_root_pathcost))
        except:
            logging.error("[!] Error. STP isn't detected.")
        return

    def detect_llmnr(self) -> None:
        print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the LLMNR protocol...")
        try:
            llmnr_packet = sniff(filter="ip dst 224.0.0.252", count=1, timeout=self.args.timeout, iface=self.args.interface)
            llmnr_sender_mac = llmnr_packet[0][Ether].src
            llmnr_sender_ip = llmnr_packet[0][IP].src
            logging.info("[*] Info: Detected LLMNR.")
            logging.info("[*] Impact: LLMNR Poisoning Attack (Stealing NetNTLM hashes, Possible SMB/HTTP/NTLM/LDAP Relay Attack)")
            logging.info("[*] Tools: Responder")
            logging.info("[*] LLMNR Sender IP: " + str(llmnr_sender_ip))
            logging.info("[*] LLMNR Sender MAC: " + str(llmnr_sender_mac))
        except:
            logging.error("[!] Error. LLMNR isn't detected.")
        return

    def detect_nbns(self) -> None:
        print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the NBT-NS protocol...")
        try:
            nbns_packet = sniff(filter="udp and port 137", count=1, timeout=self.args.timeout, iface=self.args.interface)
            nbns_sender_mac = nbns_packet[0][Ether].src
            nbns_sender_ip = nbns_packet[0][IP].src
            logging.info("[*] Info: Detected NBT-NS protocol.")
            logging.info("[*] Impact: NBT-NS Poisoning Attack (Stealing NetNTLM hashes, Possible SMB/HTTP/NTLM/LDAP Relay Attack)")
            logging.info("[*] Tools: Responder")
            logging.info("[*] NBT-NS Sender IP: " + str(nbns_sender_ip))
            logging.info("[*] NBT-NS Sender MAC: " + str(nbns_sender_mac))
        except:
            logging.error("[!] Error. NBT-NS isn't detected.")
        return 

    def detect_dhcpv6(self) -> None:
        print(Fore.GREEN + Style.BRIGHT + "\n[+] Sniffing the DHCPv6 protocol...")
        try:
            dhcpv6_packet = sniff(count = 1,lfilter=self._dhcpv6_sniff, iface=self.args.interface, timeout=self.args.timeout)
            dhcpv6_mac_address_sender = dhcpv6_packet[0][Ether].src
            dhcpv6_packet_sender = dhcpv6_packet[0][IPv6].src
            logging.info("[*] Info: Detected DHCPv6 request.")
            logging.info("[*] Impact: DNS Spoofing over IPv6 Attack (Stealing NetNTLM hashes/NTLM Relay)")
            logging.info("[*] Tools: mitm6")
            logging.info("[*] DHCPv6 Request Sender IP: " + dhcpv6_packet_sender)
            logging.info("[*] DHCPv6 Request Sender MAC: " + dhcpv6_mac_address_sender)
        except:
            logging.error("[!] Error. DHCPv6 isn't detected.")
        return

    def switch_to_promisc(self, interface) -> None:
        print(Fore.YELLOW + Style.BRIGHT + "\n[!] Switching " + Fore.BLUE + Style.BRIGHT + interface + Fore.YELLOW + Style.BRIGHT + " to promiscious mode")
        subprocess.call(["ip", "link", "set", interface, "promisc", "on"])
        ip_a_result = subprocess.check_output(["ip", "add", "show", interface])
        promisc_mode_search = re.search(r"PROMISC", ip_a_result.decode())
        if promisc_mode_search:
            print (Fore.YELLOW + Style.BRIGHT + "[*] Switched " + Fore.BLUE + Style.BRIGHT + "successfully")
        else:
            print (Fore.RED + Style.BRIGHT + "[!] Error. Not switched to promisc.")
    
    def call_scanner(self) -> None:
        '''
        Call the functions that the user has selected as command line arguments. If fullscan is selected, check it immediately
        '''
        function_list = [func for func in dir(self) if func.startswith("detect")]
        scanners = vars(self.args)
        if self.args.fullscan:
            for function_name in function_list:
                func = getattr(locals()['self'], function_name)
                func()
            return 
        for scanner in scanners.keys():
            prob_func_name = f'detect_{scanner}'
            if scanners[scanner] and prob_func_name in function_list:
                func = getattr(locals()['self'], prob_func_name)
                func()
    

def main():
    scanner = Above()
    scanner.switch_to_promisc(scanner.args.interface)
    scanner.call_scanner()

if __name__ == "__main__":
    main()