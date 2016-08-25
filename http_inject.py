from scapy.all import *

def blocked(packet):

    if "GET / HTTP/1.1" in str(packet.getlayer(Raw).load):
        ether_header = packet[Ether]
        ip_header = packet[IP]
        tcp_header = packet[TCP]

        bPacket = packet.copy()
        print "[+] Create blockPacket"

        bEther_header = bPacket[Ether]
        bIp_header = bPacket[IP]
        bTcp_header = bPacket[TCP]

        bEther_header.src = ether_header.dst;
        bEther_header.dst = ether_header.src;
        bIp_header.src = ip_header.dst;
        bIp_header.dst = ip_header.src;

        bTcp_header.sport = tcp_header.dport
        bTcp_header.dport = tcp_header.sport
        bTcp_header.seq = tcp_header.ack
        bTcp_header.ack = tcp_header.seq + len(tcp_header.load)
        del bTcp_header.load
        bTcp_header.load = "HTTP/1.1 302 Found\nLocation: https://en.wikipedia.org/wiki/HTTP_302\n\n"

        del bIp_header.chksum
        del bIp_header.len
        del bTcp_header.chksum
        bPacket.show2()
        sendp(bPacket)
        print "[+] Send blockPacket"
    
        del packet
        del bPacket
        return

buildFilter = lambda (x): TCP in x and x[TCP].dport == 80 and Raw in x
sniff(prn=blocked, lfilter=buildFilter)
