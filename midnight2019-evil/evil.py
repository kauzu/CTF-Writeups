from scapy.all import *

currentChar = 0
count = 7
def read(packet):
    global currentChar
    global count
    if packet[IP].src == "52.15.194.28":
        if packet[IP].flags:
            currentChar += 2**count
        count = count-1
        if count < 0:
            count = 7
            print(chr(currentChar), end="")
            currentChar = 0

sniff(offline='/home/markus/ctf/midnight/evil/dr-evil.pcap', prn=read, store=0)
print()



